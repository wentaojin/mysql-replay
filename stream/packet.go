package stream

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/pingcap/errors"
	"github.com/zyguan/mysql-replay/stats"
	"go.uber.org/zap"
)

type MySQLPacketHandler interface {
	Accept(ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, tcp *layers.TCP) bool
	OnPacket(pkt MySQLPacket)
	OnClose()
}

var _ MySQLPacketHandler = &defaultHandler{}

type defaultHandler struct {
	log *zap.Logger
	fsm *MySQLFSM
}

func defaultHandlerFactory(conn ConnID) MySQLPacketHandler {
	log := conn.Logger("mysql-stream")
	log.Info("new stream")
	return &defaultHandler{log: log, fsm: NewMySQLFSM(log)}
}

func (h *defaultHandler) Accept(ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, tcp *layers.TCP) bool {
	return true
}

func (h *defaultHandler) OnPacket(pkt MySQLPacket) {
	h.fsm.Handle(pkt)
	msg := "packet"
	if pkt.Len > 0 {
		dump := hex.Dump(pkt.Data)
		lines := strings.Split(strings.TrimSpace(dump), "\n")
		if len(lines) > 6 {
			abbr := lines[:3]
			abbr = append(abbr, "...")
			abbr = append(abbr, lines[len(lines)-3:]...)
			lines = abbr
		}
		msg += "\n\t" + strings.Join(lines, "\n\t") + "\n"
	}
	h.log.Info(msg,
		zap.Time("time", pkt.Time),
		zap.String("dir", pkt.Dir.String()),
		zap.Int("len", pkt.Len),
		zap.Int("seq", pkt.Seq),
	)
}

func (h *defaultHandler) OnClose() {
	h.log.Info("close")
}

func RejectConn(conn ConnID) MySQLPacketHandler {
	return &rejectHandler{}
}

var _ MySQLPacketHandler = &rejectHandler{}

type rejectHandler struct{}

func (r *rejectHandler) Accept(ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, tcp *layers.TCP) bool {
	return false
}

func (r *rejectHandler) OnPacket(pkt MySQLPacket) {}

func (r *rejectHandler) OnClose() {}

type ReplayOptions struct {
	DryRun    bool
	TargetDSN string
	FilterIn  string
	FilterOut string
}

func (o ReplayOptions) NewPacketHandler(conn ConnID) MySQLPacketHandler {
	log := conn.Logger("mysql-stream")
	rh := &replayHandler{ctx: context.Background(), opts: o, conn: conn, log: log, fsm: NewMySQLFSM(log)}
	if len(o.FilterIn) >= 0 {
		if p, err := regexp.Compile(o.FilterIn); err != nil {
			log.Warn("invalid filter-in regexp", zap.Error(err))
		} else {
			rh.filter = func(s string) bool {
				return p.FindStringIndex(s) != nil
			}
		}
	}
	if len(o.FilterOut) > 0 {
		if p, err := regexp.Compile(o.FilterOut); err != nil {
			log.Warn("invalid filter-out regexp", zap.Error(err))
		} else {
			if filter := rh.filter; filter != nil {
				rh.filter = func(s string) bool {
					return filter(s) && p.FindStringIndex(s) == nil
				}
			} else {
				rh.filter = func(s string) bool {
					return p.FindStringIndex(s) == nil
				}
			}
		}
	}
	if o.DryRun {
		log.Debug("fake connect to target db", zap.String("dsn", o.TargetDSN))
		return rh
	}
	var err error

	rh.log.Info("open database to " + rh.opts.TargetDSN)
	rh.db, err = sql.Open("mysql", o.TargetDSN)
	if err != nil {
		log.Error("reject connection due to error",
			zap.String("dsn", o.TargetDSN), zap.Error(err))
		return RejectConn(conn)
	}
	if err := rh.db.Ping(); err != nil {
		return RejectConn(conn)
	}
	stats.Add(stats.Connections, 1)
	return rh
}

var _ MySQLPacketHandler = &replayHandler{}

type Conn struct {
	sync.RWMutex
	conn  *sql.Conn
	stmts map[uint32]statement
	// conn use lastest time
	lastUsed time.Time
}

type statement struct {
	query  string
	handle *sql.Stmt
}

func NewConn(conn *sql.Conn) *Conn {
	return &Conn{
		conn:  conn,
		stmts: make(map[uint32]statement),
	}
}

func (c *Conn) UpdateLastUsed() {
	c.Lock()
	defer c.Unlock()
	c.lastUsed = time.Now()
}

func (c *Conn) GetLastUsed() time.Time {
	c.RLock()
	defer c.RUnlock()
	return c.lastUsed
}

type replayHandler struct {
	ctx    context.Context
	opts   ReplayOptions
	conn   ConnID
	fsm    *MySQLFSM
	log    *zap.Logger
	db     *sql.DB
	dbConn sync.Map
	filter func(s string) bool
}

func (rh *replayHandler) Accept(ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, tcp *layers.TCP) bool {
	return true
}

func (rh *replayHandler) OnPacket(pkt MySQLPacket) {
	rh.fsm.Handle(pkt)
	if !rh.fsm.Ready() || !rh.fsm.Changed() {
		return
	}
	switch rh.fsm.State() {
	case StateComQuery:
		rh.l(pkt.Dir).Warn("execute query",
			zap.Any("state", rh.fsm.state),
			zap.Uint32("id", rh.fsm.stmt.ID),
			zap.String("sql", rh.fsm.stmt.Query),
			zap.Any("params", rh.fsm.params),
			zap.Any("maps", rh.fsm.stmts))
		if err := rh.execute(rh.ctx, rh.connID(), rh.fsm.query); err != nil {
			rh.l(pkt.Dir).Error("execute query",
				zap.String("sql", rh.fsm.query),
				zap.Error(err))
		}
	case StateComStmtExecute:
		rh.l(pkt.Dir).Warn("execute stmt query",
			zap.Any("state", rh.fsm.state),
			zap.Uint32("id", rh.fsm.stmt.ID),
			zap.String("sql", rh.fsm.stmt.Query),
			zap.Any("params", rh.fsm.params),
			zap.Any("maps", rh.fsm.stmts))
		if err := rh.stmtExecute(rh.ctx, rh.connID(), rh.fsm.stmt.ID, rh.fsm.params); err != nil {
			rh.l(pkt.Dir).Error("execute stmt query",
				zap.Uint32("id", rh.fsm.stmt.ID),
				zap.String("sql", rh.fsm.query),
				zap.Any("params", rh.fsm.params),
				zap.Error(err))
		}
	case StateComStmtClose:
		rh.l(pkt.Dir).Warn("closed stmt query",
			zap.Any("state", rh.fsm.state),
			zap.Uint32("id", rh.fsm.stmt.ID),
			zap.String("sql", rh.fsm.stmt.Query),
			zap.Any("params", rh.fsm.params),
			zap.Any("maps", rh.fsm.stmts))
		if err := rh.stmtClose(rh.connID(), rh.fsm.stmt.ID); err != nil {
			rh.l(pkt.Dir).Error("closed stmt query",
				zap.Uint32("id", rh.fsm.stmt.ID),
				zap.String("sql", rh.fsm.query),
				zap.Any("params", rh.fsm.params),
				zap.Error(err))
		}
	case StateComStmtPrepare0, StateComStmtPrepare1:
		rh.l(pkt.Dir).Warn("prepare stmt query",
			zap.Any("state", rh.fsm.state),
			zap.Uint32("id", rh.fsm.stmt.ID),
			zap.String("sql", rh.fsm.stmt.Query),
			zap.Any("params", rh.fsm.params),
			zap.Any("maps", rh.fsm.stmts))
		// StateComStmtPrepare0 indicates that the MySQLFSM prepare process has been entered.
		// After the process is completed, the state is set to StateComStmtPrepare1. Therefore, you only need to monitor the statement of StateComStmtPrepare1.
		if err := rh.stmtPrepare(rh.ctx, rh.connID(), rh.fsm.stmt.ID, rh.fsm.stmt.Query); err != nil {
			rh.l(pkt.Dir).Error("prepare stmt query",
				zap.Uint32("id", rh.fsm.stmt.ID),
				zap.String("sql", rh.fsm.query),
				zap.Any("params", rh.fsm.params),
				zap.Error(err))
		}
	case StateComQuit:
		rh.l(pkt.Dir).Warn("quit command query",
			zap.Any("state", rh.fsm.state),
			zap.Uint32("id", rh.fsm.stmt.ID),
			zap.String("sql", rh.fsm.stmt.Query),
			zap.Any("params", rh.fsm.params),
			zap.Any("maps", rh.fsm.stmts))
		if err := rh.quitConn(rh.connID()); err != nil {
			rh.l(pkt.Dir).Error("quit command query",
				zap.Uint32("id", rh.fsm.stmt.ID),
				zap.String("sql", rh.fsm.query),
				zap.Any("params", rh.fsm.params),
				zap.Error(err))
		}
	case StateHandshake0, StateHandshake1:
		rh.l(pkt.Dir).Warn("handshake event",
			zap.Int("state", rh.fsm.state),
			zap.Uint32("id", rh.fsm.Stmt().ID),
			zap.String("schema", rh.fsm.schema),
			zap.String("sql", rh.fsm.Stmt().Query),
			zap.Any("params", rh.fsm.StmtParams()),
			zap.String("sql", rh.fsm.stmt.Query),
			zap.Any("maps", rh.fsm.stmts))
		// StateHandshake0 indicates the start of the MySQLFSM process. When the process is complete and the connection is normal, fsm.schema is set to ok and the state is changed to StateHandshake1.
		if err := rh.handshake(rh.ctx, rh.connID()); err != nil {
			rh.l(pkt.Dir).Error("handshake query",
				zap.Error(err))
		}
	default:
		rh.l(pkt.Dir).Warn("unknown event",
			zap.Int("state", rh.fsm.state),
			zap.Uint32("id", rh.fsm.Stmt().ID),
			zap.String("schema", rh.fsm.schema),
			zap.String("sql", rh.fsm.Stmt().Query),
			zap.Any("params", rh.fsm.StmtParams()),
			zap.String("sql", rh.fsm.stmt.Query),
			zap.Any("maps", rh.fsm.stmts))
	}
}

func (rh *replayHandler) handshake(ctx context.Context, connID string) error {
	_, err := rh.getConn(ctx, connID)
	return err
}

func (rh *replayHandler) execute(ctx context.Context, connID, query string) error {
	if rh.filter != nil && !rh.filter(query) {
		stats.Add(stats.SkippedQueries, 1)
		return nil
	}
	conn, err := rh.getConn(ctx, connID)
	if err != nil {
		return err
	}

	stats.Add(stats.Queries, 1)
	stats.Add(stats.ConnRunning, 1)
	_, err = conn.ExecContext(ctx, query)
	stats.Add(stats.ConnRunning, -1)
	if err != nil {
		stats.Add(stats.FailedQueries, 1)
		return errors.Trace(err)
	}
	return nil
}

func (rh *replayHandler) getConn(ctx context.Context, connID string) (*sql.Conn, error) {
	if rh.db == nil {
		return nil, fmt.Errorf("reject connection due to error, the dsn [%s] database not open", rh.opts.TargetDSN)
	}

	conn, ok := rh.dbConn.Load(connID)
	if ok {
		conn.(*Conn).Lock()
		defer conn.(*Conn).Unlock()
		if conn.(*Conn).conn != nil {
			rh.log.Info("get connection to " + connID)
			conn.(*Conn).UpdateLastUsed()
			return conn.(*Conn).conn, nil
		} else {
			conn, err := rh.db.Conn(ctx)
			if err != nil {
				return nil, errors.Trace(err)
			}
			newConn := NewConn(conn)
			newConn.UpdateLastUsed()

			rh.dbConn.Store(connID, newConn)
			rh.log.Info("open connection to " + rh.opts.TargetDSN)
			stats.Add(stats.Connections, 1)

			return conn, nil
		}
	} else {
		conn, err := rh.db.Conn(ctx)
		if err != nil {
			return nil, errors.Trace(err)
		}
		newConn := NewConn(conn)
		newConn.UpdateLastUsed()

		rh.dbConn.Store(connID, newConn)
		rh.log.Info("open connection to " + rh.opts.TargetDSN)
		stats.Add(stats.Connections, 1)

		return conn, nil
	}
}

func (rh *replayHandler) connID() string {
	return fmt.Sprintf("%s:%s", rh.conn.HashStr(), rh.conn.SrcAddr())
}

func (rh *replayHandler) stmtExecute(ctx context.Context, connID string, id uint32, params []interface{}) error {
	stmt, err := rh.getStmt(ctx, connID, id)
	if err != nil {
		if rh.filter != nil && strings.HasPrefix(err.Error(), "no such statement") {
			stats.Add(stats.SkippedStmtExecutes, 1)
			return nil
		}
		return err
	}

	stats.Add(stats.StmtExecutes, 1)
	stats.Add(stats.ConnRunning, 1)
	_, err = stmt.ExecContext(ctx, params...)
	stats.Add(stats.ConnRunning, -1)
	if err != nil {
		stats.Add(stats.FailedStmtExecutes, 1)
		return errors.Trace(err)
	}
	return nil
}

func (rh *replayHandler) stmtPrepare(ctx context.Context, connID string, id uint32, query string) error {
	if rh.filter != nil && !rh.filter(query) {
		stats.Add(stats.SkippedStmtPrepares, 1)
		return nil
	}

	conn, ok := rh.dbConn.Load(connID)
	if !ok {
		return fmt.Errorf("no such conn id [%s]", connID)
	}

	conn.(*Conn).Lock()
	defer conn.(*Conn).Unlock()

	stmt, ok := conn.(*Conn).stmts[id]
	if ok && (stmt.query == query && stmt.handle != nil) {
		conn.(*Conn).UpdateLastUsed()
		rh.log.Warn("preapre stmt reuse", zap.Uint32("id", id), zap.String("query", query), zap.String("stmt existed", "skip prepare"))
		return nil
	}

	stmt.query = query
	if stmt.handle != nil {
		stmt.handle.Close()
		stmt.handle = nil
	}

	delete(conn.(*Conn).stmts, id)
	prepareConn, err := rh.getConn(ctx, connID)
	if err != nil {
		return err
	}
	stats.Add(stats.StmtPrepares, 1)
	stmt.handle, err = prepareConn.PrepareContext(ctx, stmt.query)
	if err != nil {
		stats.Add(stats.FailedStmtPrepares, 1)
		return errors.Trace(err)
	}
	conn.(*Conn).stmts[id] = stmt
	return nil
}

func (rh *replayHandler) stmtClose(connID string, id uint32) error {
	conn, ok := rh.dbConn.Load(connID)
	if !ok {
		return fmt.Errorf("no such conn id [%s]", connID)
	}

	conn.(*Conn).Lock()
	defer conn.(*Conn).Unlock()

	stmt, ok := conn.(*Conn).stmts[id]
	if !ok {
		return fmt.Errorf("no such conn id [%s] and stmt id [%d]", connID, id)
	}
	if stmt.handle != nil {
		stmt.handle.Close()
		stmt.handle = nil
	}
	delete(conn.(*Conn).stmts, id)
	conn.(*Conn).UpdateLastUsed()
	return nil
}

func (rh *replayHandler) quitConn(connID string) error {
	conn, ok := rh.dbConn.Load(connID)
	if !ok {
		return fmt.Errorf("no such conn id [%s]", connID)
	}

	conn.(*Conn).Lock()
	defer conn.(*Conn).Unlock()

	conn.(*Conn).conn.Raw(func(driverConn interface{}) error {
		if dc, ok := driverConn.(io.Closer); ok {
			dc.Close()
		}
		return nil
	})
	conn.(*Conn).conn.Close()
	conn = nil
	stats.Add(stats.Connections, -1)

	return nil
}

func (rh *replayHandler) getStmt(ctx context.Context, connID string, id uint32) (*sql.Stmt, error) {
	conn, ok := rh.dbConn.Load(connID)
	if !ok {
		return nil, fmt.Errorf("no such conn id [%s]", connID)
	}
	conn.(*Conn).Lock()
	defer conn.(*Conn).Unlock()

	stmt, ok := conn.(*Conn).stmts[id]

	if ok && stmt.handle != nil {
		conn.(*Conn).UpdateLastUsed()
		return stmt.handle, nil
	} else if !ok {
		return nil, errors.Errorf("no such statement #%d", id)
	}
	preConn, err := rh.getConn(ctx, connID)
	if err != nil {
		return nil, err
	}
	stmt.handle, err = preConn.PrepareContext(ctx, stmt.query)
	if err != nil {
		return nil, errors.Trace(err)
	}
	conn.(*Conn).stmts[id] = stmt
	return stmt.handle, nil
}

func (rh *replayHandler) OnClose() {
	rh.log.Info("close connection to " + rh.opts.TargetDSN)
	if rh.db != nil {
		rh.db.Close()
		stats.Add(stats.Connections, -1)
	}
}

func (rh *replayHandler) l(dir reassembly.TCPFlowDirection) *zap.Logger {
	return rh.log.With(zap.String("dir", dir.String()))
}
