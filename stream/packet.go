package stream

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
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
	rh := &replayHandler{lock: &sync.Mutex{}, opts: o, conn: conn, log: log, fsm: NewMySQLFSM(log), stmts: make(map[uint32]*sql.Stmt)}
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
	rh.db, err = sql.Open("mysql", o.TargetDSN)
	if err != nil {
		log.Error("reject connection due to error",
			zap.String("dsn", o.TargetDSN), zap.Error(err))
		return RejectConn(conn)
	}
	rh.log.Debug("open connection to " + rh.opts.TargetDSN)
	stats.Add(stats.Connections, 1)
	return rh
}

var _ MySQLPacketHandler = &replayHandler{}

type replayHandler struct {
	lock   *sync.Mutex
	opts   ReplayOptions
	conn   ConnID
	fsm    *MySQLFSM
	log    *zap.Logger
	db     *sql.DB
	filter func(s string) bool
	stmts  map[uint32]*sql.Stmt
}

func (rh *replayHandler) Accept(ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, tcp *layers.TCP) bool {
	return true
}

func (rh *replayHandler) OnPacket(pkt MySQLPacket) {
	rh.lock.Lock()
	defer rh.lock.Unlock()

	rh.fsm.Handle(pkt)
	if !rh.fsm.Ready() || !rh.fsm.Changed() {
		return
	}
	switch rh.fsm.State() {
	case StateComQuery:
		stats.Add(stats.Queries, 1)
		query := rh.fsm.Query()
		if rh.filter != nil && !rh.filter(query) {
			return
		}
		if rh.db == nil {
			rh.l(pkt.Dir).Info("execute query", zap.String("sql", query))
			return
		}
		if _, err := rh.db.Exec(query); err != nil {
			rh.l(pkt.Dir).Error("execute query",
				zap.String("sql", query),
				zap.Error(err))
			stats.Add(stats.FailedQueries, 1)
		}
	case StateComStmtExecute:
		rh.log.Warn("execute stmt query",
			zap.Uint32("id", rh.fsm.Stmt().ID),
			zap.String("sql", rh.fsm.Stmt().Query),
			zap.Any("params", rh.fsm.StmtParams()))

		stats.Add(stats.StmtExecutes, 1)
		stmt := rh.getStmt(rh.fsm.Stmt().ID)
		if stmt != nil && len(rh.fsm.StmtParams()) > 0 {
			if _, err := stmt.Exec(rh.fsm.StmtParams()...); err != nil {
				rh.l(pkt.Dir).Error("stmt execute query",
					zap.String("sql", rh.fsm.Stmt().Query),
					zap.Any("params", rh.fsm.StmtParams()),
					zap.Error(err))
				stats.Add(stats.FailedStmtExecutes, 1)
			}
		} else if stmt == nil && len(rh.fsm.StmtParams()) > 0 {
			stats.Add(stats.StmtPrepares, 1)
			query := rh.fsm.Stmt().Query
			if rh.filter != nil && !rh.filter(query) {
				return
			}
			if err := rh.prepareStmt(rh.fsm.Stmt().ID, query); err != nil {
				rh.l(pkt.Dir).Error("stmt execute query",
					zap.String("sql", rh.fsm.Stmt().Query),
					zap.Any("params", rh.fsm.StmtParams()),
					zap.Error(err))
				stats.Add(stats.FailedStmtPrepares, 1)
			}
			stmt := rh.getStmt(rh.fsm.Stmt().ID)
			if _, err := stmt.Exec(rh.fsm.StmtParams()...); err != nil {
				rh.l(pkt.Dir).Error("stmt execute query",
					zap.String("sql", rh.fsm.Stmt().Query),
					zap.Any("params", rh.fsm.StmtParams()),
					zap.Error(err))
				stats.Add(stats.FailedStmtExecutes, 1)
			}
		} else {
			rh.l(pkt.Dir).Error("stmt execute query",
				zap.String("sql", rh.fsm.Stmt().Query),
				zap.Any("params", rh.fsm.StmtParams()),
				zap.Any("stmt", rh.fsm.stmts),
				zap.Error(fmt.Errorf("stmt execute query error")))
			stats.Add(stats.FailedStmtExecutes, 1)
		}
	case StateComStmtClose:
		stats.Add(stats.StmtExecutes, 1)
		if err := rh.closeStmt(rh.fsm.Stmt().ID); err != nil {
			rh.l(pkt.Dir).Error("close stmt query",
				zap.Uint32("id", rh.fsm.Stmt().ID),
				zap.String("sql", rh.fsm.Stmt().Query),
				zap.Any("params", rh.fsm.StmtParams()),
				zap.Any("stmt", rh.fsm.stmts),
				zap.Error(err))
			stats.Add(stats.FailedStmtExecutes, 1)
		}
	case StateComStmtPrepare0:
		// query := rh.fsm.Stmt().Query
		// if rh.filter != nil && !rh.filter(query) {
		// 	return
		// }
		rh.log.Warn("prepare stmt query0",
			zap.Uint32("id", rh.fsm.Stmt().ID),
			zap.String("sql", rh.fsm.Stmt().Query),
			zap.Any("params", rh.fsm.StmtParams()),
			zap.Any("stmt", rh.getStmt(rh.fsm.Stmt().ID)))

		if rh.getStmt(rh.fsm.Stmt().ID) == nil {
			stats.Add(stats.StmtPrepares, 1)
			if err := rh.prepareStmt(rh.fsm.Stmt().ID, rh.fsm.Stmt().Query); err != nil {
				rh.l(pkt.Dir).Error("prepare stmt query",
					zap.Uint32("id", rh.fsm.Stmt().ID),
					zap.String("sql", rh.fsm.Stmt().Query),
					zap.Error(err))
				stats.Add(stats.FailedStmtPrepares, 1)
			}
		}
	case StateComStmtPrepare1:
		rh.log.Warn("prepare stmt query0",
			zap.Uint32("id", rh.fsm.Stmt().ID),
			zap.String("sql", rh.fsm.Stmt().Query),
			zap.Any("params", rh.fsm.StmtParams()),
			zap.Any("stmt", rh.getStmt(rh.fsm.Stmt().ID)))
	case StateComQuit:
		rh.OnClose()
		rh.log.Warn("quit command query", zap.String("close connection", rh.opts.TargetDSN))
		// case StateHandshake0, StateHandshake1:
		// 	return
		// default:
		// 	return
	}
}

func (rh *replayHandler) prepareStmt(id uint32, sqlStr string) error {
	rh.lock.Lock()
	defer rh.lock.Unlock()
	stmt, err := rh.db.Prepare(sqlStr)
	if err != nil {
		return err
	}
	rh.stmts[id] = stmt
	return nil
}

func (rh *replayHandler) getStmt(id uint32) *sql.Stmt {
	rh.lock.Lock()
	defer rh.lock.Unlock()

	if stmt, ok := rh.stmts[id]; ok {
		return stmt
	}
	return nil
}

func (rh *replayHandler) closeStmt(id uint32) error {
	rh.lock.Lock()
	defer rh.lock.Unlock()

	if stmt, ok := rh.stmts[id]; ok {
		if err := stmt.Close(); err != nil {
			return err
		}
	}
	delete(rh.stmts, id)
	return nil
}

func (rh *replayHandler) OnClose() {
	rh.lock.Lock()
	defer rh.lock.Unlock()

	rh.log.Debug("close connection to " + rh.opts.TargetDSN)
	if rh.db != nil {
		rh.db.Close()
		stats.Add(stats.Connections, -1)
	}
	// reset
	rh.stmts = make(map[uint32]*sql.Stmt)
}

func (rh *replayHandler) l(dir reassembly.TCPFlowDirection) *zap.Logger {
	return rh.log.With(zap.String("dir", dir.String()))
}
