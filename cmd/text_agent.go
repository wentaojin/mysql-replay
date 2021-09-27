package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/pingcap/errors"
	"github.com/spf13/cobra"
	"github.com/zyguan/mysql-replay/stats"
	"go.uber.org/zap"
)

type playTaskMeta struct {
	DSN          string  `json:"dsn"`
	ID           uint64  `json:"id"`
	TS           int64   `json:"ts"`
	MaxLineSize  int64   `json:"max_line_size"`
	QueryTimeout int64   `json:"query_timeout"`
	Speed        float64 `json:"speed"`
}

type playTask struct {
	worker   *playWorker
	form     *multipart.Form
	finished uint32
}

func taskFromRequest(req *http.Request) (*playTask, error) {
	defer req.Body.Close()

	_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		return nil, errors.Trace(err)
	}
	r := multipart.NewReader(req.Body, params["boundary"])
	form, err := r.ReadForm(0)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var (
		task playTask
		meta playTaskMeta
	)

	as := form.Value["meta"]
	if len(as) < 1 {
		return nil, errors.New("meta field is missing")
	}
	err = json.Unmarshal([]byte(as[0]), &meta)
	if err != nil {
		return nil, errors.Trace(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	task.worker = &playWorker{
		playConfig: playConfig{
			Speed:         meta.Speed,
			MaxLineSize:   int(meta.MaxLineSize),
			QueryTimeout:  time.Duration(meta.QueryTimeout) * time.Millisecond,
			PlayStartTime: time.Now().UnixNano() / int64(time.Millisecond),
			OrigStartTime: meta.TS,
		},
		log:   zap.L().Named(fmt.Sprintf("%016x", meta.ID)),
		wg:    &wg,
		ts:    meta.TS,
		id:    meta.ID,
		stmts: make(map[uint64]statement),
	}
	task.worker.MySQLConfig, err = mysql.ParseDSN(meta.DSN)
	if err != nil {
		return nil, errors.Trace(err)
	}
	task.form = form
	return &task, nil
}

func (task *playTask) openData() (io.ReadCloser, error) {
	if task.form == nil {
		return os.Open(task.worker.src)
	}
	fhs := task.form.File["data"]
	if len(fhs) == 0 {
		return nil, errors.New("data field is missing")
	}
	return fhs[0].Open()
}

func (task *playTask) buildRequest(url string, in io.ReadCloser) (*http.Request, error) {
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
		err = json.NewEncoder(meta).Encode(playTaskMeta{
			DSN:          task.worker.MySQLConfig.FormatDSN(),
			ID:           task.worker.id,
			TS:           task.worker.ts,
			MaxLineSize:  int64(task.worker.MaxLineSize),
			QueryTimeout: int64(task.worker.QueryTimeout / time.Millisecond),
			Speed:        task.worker.Speed,
		})
		if err != nil {
			zap.L().Error("write meta field", zap.Error(err))
			w.CloseWithError(err)
			return
		}
		data, err := body.CreateFormFile("data", task.worker.src)
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

func (task *playTask) run() {
	defer func() {
		atomic.StoreUint32(&task.finished, 1)
		task.form.RemoveAll()
	}()
	r, err := task.openData()
	if err != nil {
		zap.L().Error("open event file", zap.Error(err))
		return
	}
	defer r.Close()
	task.worker.start(context.Background(), r)
}

type playJobStatus struct {
	Total    int              `json:"total"`
	Finished int              `json:"finished"`
	Stats    map[string]int64 `json:"stats"`
}

type playTaskStore struct {
	tasks map[string][]*playTask
	lock  sync.Mutex
}

func newTaskStore() *playTaskStore {
	return &playTaskStore{tasks: make(map[string][]*playTask)}
}

func (store *playTaskStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		store.handleJobStatusQuery(w, r)
	} else if r.Method == http.MethodPost {
		store.handleTaskSubmission(w, r)
	} else {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (store *playTaskStore) handleTaskSubmission(w http.ResponseWriter, r *http.Request) {
	task, err := taskFromRequest(r)
	if err != nil {
		zap.L().Error("build task from request", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	go task.run()
	store.lock.Lock()
	store.tasks[r.URL.Path] = append(store.tasks[r.URL.Path], task)
	store.lock.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (store *playTaskStore) handleJobStatusQuery(w http.ResponseWriter, r *http.Request) {
	var status playJobStatus
	store.lock.Lock()
	status.Total = len(store.tasks[r.URL.Path])
	for _, task := range store.tasks[r.URL.Path] {
		if atomic.LoadUint32(&task.finished) == 1 {
			status.Finished += 1
		}
	}
	store.lock.Unlock()
	status.Stats = stats.Dump()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func NewTextAgentCommand() *cobra.Command {
	var (
		addr string
	)
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Start a text play agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			http.Handle("/", newTaskStore())
			return http.ListenAndServe(addr, nil)
		},
	}
	cmd.Flags().StringVar(&addr, "address", ":9000", "address to listen on")
	return cmd
}
