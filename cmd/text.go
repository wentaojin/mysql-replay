package cmd

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"github.com/pingcap/errors"
	"github.com/spf13/cobra"
	"github.com/zyguan/mysql-replay/event"
	"github.com/zyguan/mysql-replay/stats"
	"github.com/zyguan/mysql-replay/stream"
	"go.uber.org/zap"
)

func NewTextDumpCommand() *cobra.Command {
	var (
		options = stream.FactoryOptions{Synchronized: true}
		output  string
	)
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump pcap files",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				out = os.Stdout
				err error
			)
			if len(args) == 0 {
				return cmd.Help()
			}
			if len(output) > 0 {
				out, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
				if err != nil {
					return err
				}
				defer out.Close()
			}

			factory := stream.NewFactoryFromEventHandler(func(conn stream.ConnID) stream.MySQLEventHandler {
				return &textDumpHandler{
					log: conn.Logger("text-dump"),
					out: out,
					buf: make([]byte, 0, 4096),
				}
			}, options)
			pool := reassembly.NewStreamPool(factory)
			assembler := reassembly.NewAssembler(pool)

			dumpFrom := func(name string) error {
				f, err := pcap.OpenOffline(name)
				if err != nil {
					return err
				}
				defer f.Close()
				src := gopacket.NewPacketSource(f, f.LinkType())
				for pkt := range src.Packets() {
					layer := pkt.Layer(layers.LayerTypeTCP)
					if layer == nil {
						continue
					}
					tcp := layer.(*layers.TCP)
					assembler.AssembleWithContext(pkt.NetworkLayer().NetworkFlow(), tcp, captureContext(pkt.Metadata().CaptureInfo))
				}
				return nil
			}

			for _, in := range args {
				err = dumpFrom(in)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")
	cmd.Flags().BoolVar(&options.ForceStart, "force-start", false, "accept streams even if no SYN have been seen")
	return cmd
}

type textDumpHandler struct {
	log *zap.Logger
	out io.Writer
	buf []byte
}

func (h *textDumpHandler) OnEvent(e event.MySQLEvent) {
	var err error
	h.buf = h.buf[:0]
	h.buf, err = event.AppendEvent(h.buf, e)
	if err != nil {
		h.log.Error("failed to dump event", zap.Any("value", e), zap.Error(err))
		return
	}
	h.out.Write(h.buf)
	h.out.Write([]byte{'\n'})
}

func (h *textDumpHandler) OnClose() {}

func NewTextPlayCommand() *cobra.Command {
	var (
		control        = &playControl{wg: new(sync.WaitGroup), workers: map[uint64]*playWorker{}}
		targetDSN      string
		reportInterval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "play",
		Short: "Play mysql events from text files",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			var (
				done = make(chan struct{})
				err  error
			)
			control.log = zap.L()
			if !control.DryRun {
				control.cfg, err = mysql.ParseDSN(targetDSN)
				if err != nil {
					return err
				}
			}

			control.wg.Add(1)
			go func() {
				fields := make([]zap.Field, 0, 7)
				ticker := time.NewTicker(reportInterval)
				load := func() {
					metrics := stats.Dump()
					fields = fields[:0]
					for _, name := range []string{
						stats.Connections, stats.Queries, stats.StmtExecutes, stats.StmtPrepares,
						stats.FailedQueries, stats.FailedStmtExecutes, stats.FailedStmtPrepares,
					} {
						fields = append(fields, zap.Int64(name, metrics[name]))
					}
				}
				defer func() {
					ticker.Stop()
					control.wg.Done()
					control.wg.Wait()
					load()
					control.log.Info("done", fields...)
				}()
				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						load()
						control.log.Info("stats", fields...)
					}
				}
			}()

			err = control.Play(context.Background(), args...)
			if err != nil {
				return err
			}
			close(done)
			control.Stop()
			return nil
		},
	}
	cmd.Flags().StringVar(&targetDSN, "target-dsn", "", "target dsn")
	cmd.Flags().Float64Var(&control.Speed, "speed", 1, "speed ratio")
	cmd.Flags().BoolVar(&control.DryRun, "dry-run", false, "dry run mode (just print events)")
	cmd.Flags().UintVar(&control.QSize, "qsize", 32, "event queue size for each connection")
	cmd.Flags().IntVar(&control.MaxLineSize, "max-line-size", 16777216, "max line size")
	cmd.Flags().DurationVar(&control.QueryTimeout, "query-timeout", time.Minute, "timeout for a single query")
	cmd.Flags().DurationVar(&reportInterval, "report-interval", 5*time.Second, "report interval")
	return cmd
}

type playControl struct {
	DryRun       bool
	QSize        uint
	Speed        float64
	MaxLineSize  int
	QueryTimeout time.Duration

	playStartedAt int64
	emitStartedAt int64

	log *zap.Logger
	cfg *mysql.Config

	wg      *sync.WaitGroup
	workers map[uint64]*playWorker
}

func (pc *playControl) Play(ctx context.Context, inputs ...string) error {
	pc.playStartedAt = time.Now().UnixNano() / int64(time.Millisecond)
	pc.emitStartedAt = 0
	for _, in := range inputs {
		err := pc.playOne(ctx, in)
		if err != nil {
			return errors.Annotatef(err, "play %q", in)
		}
	}
	return nil
}

func (pc *playControl) Stop() {
	for id, pw := range pc.workers {
		pw.stop()
		delete(pc.workers, id)
	}
	pc.wg.Wait()
}

func (pc *playControl) playOne(ctx context.Context, input string) error {
	in, err := os.Open(input)
	if err != nil {
		return err
	}
	defer in.Close()

	var (
		e      event.MySQLEvent
		params = make([]interface{}, 0, 8)
	)

	sc := bufio.NewScanner(in)
	if pc.MaxLineSize > 0 {
		buf := make([]byte, 0, 4096)
		sc.Buffer(buf, pc.MaxLineSize)
	}
	for sc.Scan() {
		_, err = event.ScanEvent(sc.Text(), 0, e.Reset(params[:0]))
		if err != nil {
			return err
		}
		if pc.emitStartedAt == 0 {
			pc.emitStartedAt = e.Time
		}
		for pc.Speed > 0 && float64(time.Now().UnixNano()/int64(time.Millisecond)-pc.playStartedAt)*pc.Speed < float64(e.Time-pc.emitStartedAt) {
			time.Sleep(time.Millisecond)
		}
		if pc.DryRun {
			pc.log.Info(e.String())
			continue
		}
		pw := pc.workers[e.Conn]
		if pw == nil {
			pw = &playWorker{
				id:      e.Conn,
				log:     pc.log.With(zap.String("conn", fmt.Sprintf("%x", e.Conn))),
				cfg:     pc.cfg,
				wg:      pc.wg,
				timeout: pc.QueryTimeout,
				ch:      make(chan event.MySQLEvent, pc.QSize),
				stmts:   make(map[uint64]statement),
			}
			pc.workers[e.Conn] = pw
			pc.wg.Add(1)
			go pw.start(ctx)
		}
		pw.push(e)
		if e.Type == event.EventQuit {
			pw.stop()
			delete(pc.workers, e.Conn)
		}
	}
	return sc.Err()
}

type statement struct {
	query  string
	handle *sql.Stmt
}

type playWorker struct {
	log *zap.Logger
	cfg *mysql.Config

	wg *sync.WaitGroup
	ch chan event.MySQLEvent

	id      uint64
	schema  string
	params  []interface{}
	timeout time.Duration

	pool  *sql.DB
	conn  *sql.Conn
	stmts map[uint64]statement
}

func (pw *playWorker) push(e event.MySQLEvent) {
	if len(e.Params) > 0 {
		params := make([]interface{}, len(e.Params))
		copy(params, e.Params)
		e.Params = params
	}
	pw.ch <- e
}

func (pw *playWorker) stop() {
	close(pw.ch)
}

func (pw *playWorker) start(ctx context.Context) {
	defer pw.wg.Done()
	var (
		e   event.MySQLEvent
		err error
		ok  bool
	)
	pw.log.Info("new connection")
	for {
		select {
		case e, ok = <-pw.ch:
			if !ok {
				pw.log.Debug("exit normally")
				return
			}
		case <-ctx.Done():
			pw.log.Debug("exit due to context done")
			return
		}
		if pw.log.Core().Enabled(zap.DebugLevel) {
			pw.log.Debug(e.String())
		}

		switch e.Type {
		case event.EventQuery:
			err = pw.execute(ctx, e.Query)
		case event.EventStmtExecute:
			err = pw.stmtExecute(ctx, e.StmtID, e.Params)
		case event.EventStmtPrepare:
			err = pw.stmtPrepare(ctx, e.StmtID, e.Query)
		case event.EventStmtClose:
			pw.stmtClose(ctx, e.StmtID)
		case event.EventHandshake:
			err = pw.handshake(ctx, e.DB)
		case event.EventQuit:
			pw.quit()
		default:
			pw.log.Warn("unknown event", zap.Any("value", e))
			continue
		}
		if err != nil {
			if connErr := errors.Unwrap(err); connErr == sql.ErrConnDone || connErr == mysql.ErrInvalidConn || connErr == context.DeadlineExceeded {
				pw.log.Warn("reconnect after "+e.String(), zap.String("cause", connErr.Error()))
				err = pw.handshake(ctx, pw.schema)
				if err != nil {
					pw.log.Warn("reconnect error", zap.Error(err))
				}
			} else {
				pw.log.Warn("failed to apply "+e.String(), zap.Error(err))
			}
		}
	}
}

func (pw *playWorker) handshake(ctx context.Context, schema string) error {
	pw.quit()
	cfg := pw.cfg
	if len(schema) > 0 && cfg.DBName != schema {
		cfg = cfg.Clone()
		cfg.DBName = schema
	}
	pool, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return err
	}
	pw.pool = pool
	pw.schema = schema
	_, err = pw.getConn(ctx)
	return err
}

func (pw *playWorker) quit() {
	for id, stmt := range pw.stmts {
		if stmt.handle != nil {
			stmt.handle.Close()
		}
		delete(pw.stmts, id)
	}
	if pw.conn != nil {
		pw.conn.Close()
		pw.conn = nil
		stats.Add(stats.Connections, -1)
	}
	if pw.pool != nil {
		pw.pool.Close()
		pw.pool = nil
	}
}

func (pw *playWorker) execute(ctx context.Context, query string) error {
	conn, err := pw.getConn(ctx)
	if err != nil {
		return err
	}
	if pw.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, pw.timeout)
		defer cancel()
	}
	stats.Add(stats.Queries, 1)
	_, err = conn.ExecContext(ctx, query)
	if err != nil {
		stats.Add(stats.FailedQueries, 1)
		return errors.Trace(err)
	}
	return nil
}

func (pw *playWorker) stmtPrepare(ctx context.Context, id uint64, query string) error {
	stmt := pw.stmts[id]
	stmt.query = query
	if stmt.handle != nil {
		stmt.handle.Close()
		stmt.handle = nil
	}
	delete(pw.stmts, id)
	conn, err := pw.getConn(ctx)
	if err != nil {
		return err
	}
	stats.Add(stats.StmtPrepares, 1)
	stmt.handle, err = conn.PrepareContext(ctx, stmt.query)
	if err != nil {
		stats.Add(stats.FailedStmtPrepares, 1)
		return errors.Trace(err)
	}
	pw.stmts[id] = stmt
	return nil
}

func (pw *playWorker) stmtExecute(ctx context.Context, id uint64, params []interface{}) error {
	stmt, err := pw.getStmt(ctx, id)
	if err != nil {
		return err
	}
	if pw.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, pw.timeout)
		defer cancel()
	}
	stats.Add(stats.StmtExecutes, 1)
	_, err = stmt.ExecContext(ctx, params...)
	if err != nil {
		stats.Add(stats.FailedStmtExecutes, 1)
		return errors.Trace(err)
	}
	return nil
}

func (pw *playWorker) stmtClose(ctx context.Context, id uint64) {
	stmt, ok := pw.stmts[id]
	if !ok {
		return
	}
	if stmt.handle != nil {
		stmt.handle.Close()
	}
	delete(pw.stmts, id)
}

func (pw *playWorker) getConn(ctx context.Context) (*sql.Conn, error) {
	var err error
	if pw.pool == nil {
		pw.pool, err = sql.Open("mysql", pw.cfg.FormatDSN())
		if err != nil {
			return nil, err
		}
	}
	if pw.conn == nil {
		pw.conn, err = pw.pool.Conn(ctx)
		if err != nil {
			return nil, errors.Trace(err)
		}
		stats.Add(stats.Connections, 1)
	}
	return pw.conn, nil
}

func (pw *playWorker) getStmt(ctx context.Context, id uint64) (*sql.Stmt, error) {
	stmt, ok := pw.stmts[id]
	if ok && stmt.handle != nil {
		return stmt.handle, nil
	} else if !ok {
		return nil, errors.Errorf("no such statement #%d", id)
	}
	conn, err := pw.getConn(ctx)
	if err != nil {
		return nil, err
	}
	stmt.handle, err = conn.PrepareContext(ctx, stmt.query)
	if err != nil {
		return nil, errors.Trace(err)
	}
	pw.stmts[id] = stmt
	return stmt.handle, nil
}

func NewTextCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "text",
		Short: "Text format utilities",
	}
	cmd.AddCommand(NewTextDumpCommand())
	cmd.AddCommand(NewTextPlayCommand())
	return cmd
}
