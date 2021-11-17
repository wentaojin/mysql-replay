package cmd

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/pingcap/errors"
	"github.com/zyguan/mysql-replay/event"
	"github.com/zyguan/mysql-replay/stats"

	"go.uber.org/zap"
)

func NewPlayJobFromFile(src string) (*PlayJob, error) {
	info := strings.Split(filepath.Base(src), ".")
	if len(info) != 4 || info[3] != "tsv" {
		return nil, errors.New("invalid source file name: " + src)
	}
	from, err := strconv.ParseInt(info[0], 10, 64)
	if err != nil {
		return nil, errors.New("invalid source file name: " + src)
	}
	to, err := strconv.ParseInt(info[1], 10, 64)
	if err != nil {
		return nil, errors.New("invalid source file name: " + src)
	}
	id, err := strconv.ParseUint(info[2], 16, 64)
	if err != nil {
		return nil, errors.New("invalid source file name: " + src)
	}
	return &PlayJob{ID: id, From: from, To: to, Open: func() (io.ReadCloser, error) { return os.Open(src) }}, nil
}

func NewPlayJobFromRequest(req *http.Request) (*PlayJob, *multipart.Form, error) {
	_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, errors.Trace(err)
	}
	r := multipart.NewReader(req.Body, params["boundary"])
	form, err := r.ReadForm(0)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	meta := form.Value["meta"]
	if len(meta) == 0 {
		return nil, form, errors.New("meta field is missing")
	}
	data := form.File["data"]
	if len(data) == 0 {
		return nil, form, errors.New("data field is missing")
	}

	var job PlayJob
	err = json.Unmarshal([]byte(meta[0]), &job)
	if err != nil {
		return nil, form, errors.Trace(err)
	}
	job.Open = func() (io.ReadCloser, error) {
		return data[0].Open()
	}
	return &job, form, nil
}

type PlayJob struct {
	DSN          string  `json:"dsn"`
	ID           uint64  `json:"id"`
	MaxLineSize  int64   `json:"max_line_size"`
	QueryTimeout int64   `json:"query_timeout"`
	From         int64   `json:"from"`
	To           int64   `json:"to"`
	Split        int64   `json:"split"`
	Speed        float64 `json:"speed"`

	Open func() (io.ReadCloser, error) `json:"-"`
}

func (job *PlayJob) ToRequest(url string) (*http.Request, error) {
	in, err := job.Open()
	if err != nil {
		return nil, err
	}
	r, w := io.Pipe()
	body := multipart.NewWriter(w)
	go func() {
		defer in.Close()
		meta, err := body.CreateFormField("meta")
		if err != nil {
			zap.L().Error("create meta field", zap.Error(err))
			w.CloseWithError(err)
			return
		}
		err = json.NewEncoder(meta).Encode(job)
		if err != nil {
			zap.L().Error("write meta field", zap.Error(err))
			w.CloseWithError(err)
			return
		}
		data, err := body.CreateFormFile("data", fmt.Sprintf("%d.%d.%016x.tsv", job.From, job.To, job.ID))
		if err != nil {
			zap.L().Error("create data field", zap.Error(err))
			w.CloseWithError(err)
			return
		}
		_, err = io.Copy(data, in)
		if err != nil {
			zap.L().Error("write data field", zap.Error(err))
			w.CloseWithError(err)
			return
		}
		body.Close()
		w.Close()
	}()
	req, err := http.NewRequest(http.MethodPost, url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", body.FormDataContentType())
	return req, nil
}

func (job *PlayJob) Start(ctx context.Context, wg *sync.WaitGroup) []*PlayTask {
	var tasks []*PlayTask
	if job.Split <= 1 {
		tasks = append(tasks, &PlayTask{
			PlayJob: *job, stmts: map[uint64]statement{},
			log: zap.L().Named(fmt.Sprintf("task-%016x", job.ID)),
		})
	} else {
		for i := int64(0); i < job.Split; i++ {
			tasks = append(tasks, &PlayTask{
				PlayJob: *job, stmts: map[uint64]statement{}, idx: i,
				log: zap.L().Named(fmt.Sprintf("task-%016x-%02d", job.ID, i)),
			})
		}
	}
	for _, task := range tasks {
		wg.Add(1)
		go task.start(ctx, wg)
	}
	return tasks
}

type statement struct {
	query  string
	handle *sql.Stmt
}

type PlayTask struct {
	PlayJob

	idx int64
	log *zap.Logger

	schema string

	pool  *sql.DB
	conn  *sql.Conn
	stmts map[uint64]statement
}

func (task *PlayTask) debug() bool { return task.Split <= 0 }

func (task *PlayTask) start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	r, err := task.Open()
	if err != nil {
		task.log.Error("failed to open input file", zap.Error(err))
		return
	}
	defer func() {
		task.quit(false)
		stats.SetLagging(task.ID, 0)
		r.Close()
	}()
	in := bufio.NewScanner(r)
	if task.MaxLineSize > 0 {
		buf := make([]byte, 0, 4096)
		in.Buffer(buf, int(task.MaxLineSize))
	}
	startTime := time.Now().UnixNano() / int64(time.Millisecond)
	slow := false
	e := event.MySQLEvent{Params: []interface{}{}}
	for in.Scan() {
		_, err := event.ScanEvent(in.Text(), 0, e.Reset(e.Params[:0]))
		if err != nil {
			task.log.Error("failed to scan event", zap.Error(err))
			return
		}

		d, pos := task.wait(e.Time, startTime)
		if pos > 0 {
			break
		}
		if d > 0 {
			stats.Add(stats.ConnWaiting, 1)
			select {
			case <-ctx.Done():
				stats.Add(stats.ConnWaiting, -1)
				task.log.Debug("exit due to context done")
				return
			case <-time.After(d):
				stats.Add(stats.ConnWaiting, -1)
			}
			if slow {
				stats.SetLagging(task.ID, 0)
				slow = false
			}
		} else {
			select {
			case <-ctx.Done():
				task.log.Debug("exit due to context done")
				return
			default:
			}
			if d == 0 {
				stats.SetLagging(task.ID, -d)
				slow = true
			}
		}
		if task.debug() {
			task.log.Info(e.String())
			continue
		} else if task.log.Core().Enabled(zap.DebugLevel) {
			task.log.Debug(e.String())
		}

		switch e.Type {
		case event.EventQuery:
			if pos == 0 {
				err = task.execute(ctx, e.Query)
			}
		case event.EventStmtExecute:
			if pos == 0 {
				err = task.stmtExecute(ctx, e.StmtID, e.Params)
			}
		case event.EventStmtPrepare:
			err = task.stmtPrepare(ctx, e.StmtID, e.Query)
		case event.EventStmtClose:
			task.stmtClose(ctx, e.StmtID)
		case event.EventHandshake:
			task.quit(false)
			err = task.handshake(ctx, e.DB)
		case event.EventQuit:
			task.quit(false)
		default:
			task.log.Warn("unknown event", zap.Any("value", e))
			continue
		}
		if err != nil {
			if sqlErr := errors.Unwrap(err); sqlErr == context.DeadlineExceeded || sqlErr == sql.ErrConnDone || sqlErr == mysql.ErrInvalidConn {
				task.log.Warn("reconnect after "+e.String(), zap.String("schema", task.schema), zap.String("cause", sqlErr.Error()))
				task.quit(true)
				err = task.handshake(ctx, task.schema)
				if err != nil {
					task.log.Warn("reconnect error", zap.Error(err))
				}
			} else {
				mysqlErr, ok := err.(*mysql.MySQLError)
				if ok {
					cnt := stats.Add("mysql-errors."+strconv.FormatUint(uint64(mysqlErr.Number), 10), 1)
					if cnt > 50 && cnt%100 == 0 {
						task.log.Warn("too many mysql errors",
							zap.Int64("count", cnt),
							zap.Uint16("code", mysqlErr.Number),
							zap.String("message", mysqlErr.Message))
						continue
					}
				}
				task.log.Warn("failed to apply "+e.String(), zap.Error(err))
			}
		}
	}
}

func (task *PlayTask) wait(eventTS int64, startTS int64) (time.Duration, int) {
	if task.debug() {
		return 0, 0
	}
	eventStartTS := task.From
	window := (task.To - task.From) / task.Split
	remaining := (task.To - task.From) % task.Split
	eventStartTS += task.idx * window
	if task.idx == 0 {
		window += remaining
	} else {
		eventStartTS += remaining
	}
	pos := 0
	if eventTS < eventStartTS {
		pos = -1
	} else if eventTS >= eventStartTS+window {
		pos = 1
	}
	return time.Duration((float64(eventTS-eventStartTS)/task.Speed+float64(startTS))*float64(time.Millisecond) - float64(time.Now().UnixNano())), pos
}

func (task *PlayTask) open(schema string) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(task.DSN)
	if err != nil {
		return nil, err
	}
	if len(schema) > 0 && cfg.DBName != schema {
		cfg.DBName = schema
	}
	if len(cfg.DBName) == 0 {
		task.log.Info("connect with empty schema", zap.String("dsn", cfg.FormatDSN()), zap.Stack("stack"))
	}
	return sql.Open("mysql", cfg.FormatDSN())
}

func (task *PlayTask) handshake(ctx context.Context, schema string) error {
	task.schema = schema
	pool, err := task.open(schema)
	if err != nil {
		return err
	}
	task.pool = pool
	_, err = task.getConn(ctx)
	return err
}

func (task *PlayTask) quit(reconnect bool) {
	for id, stmt := range task.stmts {
		if stmt.handle != nil {
			stmt.handle.Close()
			stmt.handle = nil
		}
		if reconnect {
			task.stmts[id] = stmt
		} else {
			delete(task.stmts, id)
		}
	}
	if task.conn != nil {
		task.conn.Raw(func(driverConn interface{}) error {
			if dc, ok := driverConn.(io.Closer); ok {
				dc.Close()
			}
			return nil
		})
		task.conn.Close()
		task.conn = nil
		stats.Add(stats.Connections, -1)
	}
	if task.pool != nil {
		task.pool.Close()
		task.pool = nil
	}
}

func (task *PlayTask) execute(ctx context.Context, query string) error {
	conn, err := task.getConn(ctx)
	if err != nil {
		return err
	}
	if task.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(task.QueryTimeout)*time.Millisecond)
		defer cancel()
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

func (task *PlayTask) stmtPrepare(ctx context.Context, id uint64, query string) error {
	stmt := task.stmts[id]
	stmt.query = query
	if stmt.handle != nil {
		stmt.handle.Close()
		stmt.handle = nil
	}
	delete(task.stmts, id)
	conn, err := task.getConn(ctx)
	if err != nil {
		return err
	}
	stats.Add(stats.StmtPrepares, 1)
	stmt.handle, err = conn.PrepareContext(ctx, stmt.query)
	if err != nil {
		stats.Add(stats.FailedStmtPrepares, 1)
		return errors.Trace(err)
	}
	task.stmts[id] = stmt
	return nil
}

func (task *PlayTask) stmtExecute(ctx context.Context, id uint64, params []interface{}) error {
	stmt, err := task.getStmt(ctx, id)
	if err != nil {
		return err
	}
	if task.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(task.QueryTimeout)*time.Millisecond)
		defer cancel()
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

func (task *PlayTask) stmtClose(ctx context.Context, id uint64) {
	stmt, ok := task.stmts[id]
	if !ok {
		return
	}
	if stmt.handle != nil {
		stmt.handle.Close()
		stmt.handle = nil
	}
	delete(task.stmts, id)
}

func (task *PlayTask) getConn(ctx context.Context) (*sql.Conn, error) {
	var err error
	if task.pool == nil {
		task.pool, err = task.open(task.schema)
		if err != nil {
			return nil, err
		}
	}
	if task.conn == nil {
		task.conn, err = task.pool.Conn(ctx)
		if err != nil {
			return nil, errors.Trace(err)
		}
		stats.Add(stats.Connections, 1)
	}
	return task.conn, nil
}

func (task *PlayTask) getStmt(ctx context.Context, id uint64) (*sql.Stmt, error) {
	stmt, ok := task.stmts[id]
	if ok && stmt.handle != nil {
		return stmt.handle, nil
	} else if !ok {
		return nil, errors.Errorf("no such statement #%d", id)
	}
	conn, err := task.getConn(ctx)
	if err != nil {
		return nil, err
	}
	stmt.handle, err = conn.PrepareContext(ctx, stmt.query)
	if err != nil {
		return nil, errors.Trace(err)
	}
	task.stmts[id] = stmt
	return stmt.handle, nil
}
