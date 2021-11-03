package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
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
		options        = stream.FactoryOptions{Synchronized: true}
		output         string
		reportInterval time.Duration
		flushInterval  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump pcap files",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if len(output) > 0 {
				os.MkdirAll(output, 0755)
			}

			var (
				lock     sync.Mutex
				outFiles = make(map[string][]*textFileInfo)
				collect  = func(info *textFileInfo) {
					lock.Lock()
					outFiles[info.id] = append(outFiles[info.id], info)
					lock.Unlock()
				}
			)

			factory := stream.NewFactoryFromEventHandler(func(conn stream.ConnID) stream.MySQLEventHandler {
				log := conn.Logger("dump")
				out, err := os.CreateTemp(output, "."+conn.HashStr()+".*")
				if err != nil {
					log.Error("failed to create file for dumping events", zap.Error(err))
					return nil
				}
				return &textDumpHandler{
					conn:    conn,
					buf:     make([]byte, 0, 4096),
					log:     log,
					out:     out,
					w:       bufio.NewWriterSize(out, 1048576),
					collect: collect,
				}
			}, options)
			pool := reassembly.NewStreamPool(factory)
			assembler := reassembly.NewAssembler(pool)

			lastFlushTime := time.Time{}
			handle := func(name string) error {
				f, err := pcap.OpenOffline(name)
				if err != nil {
					return errors.Annotate(err, "open "+name)
				}
				defer f.Close()
				src := gopacket.NewPacketSource(f, f.LinkType())
				for pkt := range src.Packets() {
					if meta := pkt.Metadata(); meta != nil && meta.Timestamp.Sub(lastFlushTime) > flushInterval {
						assembler.FlushCloseOlderThan(lastFlushTime)
						lastFlushTime = meta.Timestamp
					}
					layer := pkt.Layer(layers.LayerTypeTCP)
					if layer == nil {
						continue
					}
					tcp := layer.(*layers.TCP)
					assembler.AssembleWithContext(pkt.NetworkLayer().NetworkFlow(), tcp, captureContext(pkt.Metadata().CaptureInfo))
				}
				return nil
			}

			startTime := time.Now()
			go func() {
				ticker := time.NewTicker(reportInterval)
				defer ticker.Stop()
				var (
					prvDataIn int64
					curDataIn int64
				)
				for {
					prvDataIn = curDataIn
					<-ticker.C
					curDataIn = stats.Get(stats.DataIn)
					zap.L().Info("stats",
						zap.Int64("speed", int64(float64(curDataIn-prvDataIn)*float64(time.Second)/float64(reportInterval))),
						zap.Int64(stats.DataIn, curDataIn),
						zap.Int64(stats.DataOut, stats.Get(stats.DataOut)),
						zap.Int64(stats.ComQueryError, stats.Get(stats.ComQueryError)),
						zap.Int64(stats.ComQueryTotal, stats.Get(stats.ComQueryTotal)),
						zap.Int64(stats.ComExecuteError, stats.Get(stats.ComExecuteError)),
						zap.Int64(stats.ComExecuteTotal, stats.Get(stats.ComExecuteTotal)),
						zap.Int64(stats.ComPrepareError, stats.Get(stats.ComPrepareError)),
						zap.Int64(stats.ComPrepareTotal, stats.Get(stats.ComPrepareTotal)),
						zap.Int64(stats.Packets, stats.Get(stats.Packets)))
				}
			}()

			for _, in := range args {
				zap.L().Info("processing " + in)
				err := handle(in)
				if err != nil {
					return err
				}
			}
			assembler.FlushAll()

			zap.L().Info("done",
				zap.Int64("speed", int64(float64(stats.Get(stats.DataIn))*float64(time.Second)/float64(time.Since(startTime)))),
				zap.Int64(stats.DataIn, stats.Get(stats.DataIn)),
				zap.Int64(stats.DataOut, stats.Get(stats.DataOut)),
				zap.Int64(stats.ComQueryError, stats.Get(stats.ComQueryError)),
				zap.Int64(stats.ComQueryTotal, stats.Get(stats.ComQueryTotal)),
				zap.Int64(stats.ComExecuteError, stats.Get(stats.ComExecuteError)),
				zap.Int64(stats.ComExecuteTotal, stats.Get(stats.ComExecuteTotal)),
				zap.Int64(stats.ComPrepareError, stats.Get(stats.ComPrepareError)),
				zap.Int64(stats.ComPrepareTotal, stats.Get(stats.ComPrepareTotal)),
				zap.Int64(stats.Packets, stats.Get(stats.Packets)))

			for id, files := range outFiles {
				err := mergeTextOutFiles(files)
				if err != nil {
					zap.L().Error("merge files", zap.String("session", id), zap.Error(err))
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "output directory")
	cmd.Flags().BoolVar(&options.ForceStart, "force-start", false, "accept streams even if no SYN have been seen")
	cmd.Flags().DurationVar(&reportInterval, "report-interval", 5*time.Second, "report interval")
	cmd.Flags().DurationVar(&flushInterval, "flush-interval", 3*time.Second, "flush interval")

	return cmd
}

type textFileInfo struct {
	id   string
	path string
	fst  int64
	lst  int64
}

func mergeTextOutFiles(files []*textFileInfo) error {
	if len(files) <= 1 {
		return nil
	}
	sort.Slice(files, func(i, j int) bool { return files[i].fst < files[j].fst })
	for i := 0; i+1 < len(files); i++ {
		if files[i].id != files[i+1].id {
			return errors.Errorf("cannot merge files with different session id: [%s, %s]", files[i].id, files[i+1].id)
		}
		if files[i].lst > files[i+1].fst {
			return errors.Errorf("cannot merge files with overlap: [%s, %s]", files[i].path, files[i+1].path)
		}
	}
	mergeDst := filepath.Join(
		filepath.Dir(files[0].path),
		fmt.Sprintf("%d.%d.%s.tsv", files[0].fst, files[len(files)-1].lst, files[0].id))
	out, err := os.OpenFile(mergeDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return errors.Annotate(err, "open file for merge")
	}
	defer out.Close()
	mergedFiles := make([]string, 0, len(files))
	for _, file := range files {
		f, err := os.Open(file.path)
		if err != nil {
			zap.L().Error("failed to merge file", zap.String("path", file.path), zap.Error(err))
			continue
		}
		_, err = io.Copy(out, f)
		if err != nil {
			zap.L().Error("an error occurred while copying", zap.String("path", file.path), zap.Error(err))
		} else {
			mergedFiles = append(mergedFiles, file.path)
			os.Remove(file.path)
		}
		f.Close()
	}
	if len(mergedFiles) > 0 {
		zap.L().Sugar().Infof("merge %v into %s", mergedFiles, mergeDst)
	}
	return nil
}

type textDumpHandler struct {
	conn stream.ConnID
	buf  []byte
	log  *zap.Logger
	out  *os.File
	w    *bufio.Writer

	fst int64
	lst int64

	collect func(*textFileInfo)
}

func (h *textDumpHandler) OnEvent(e event.MySQLEvent) {
	var err error
	h.buf = h.buf[:0]
	h.buf, err = event.AppendEvent(h.buf, e)
	if err != nil {
		h.log.Error("failed to dump event", zap.Any("value", e), zap.Error(err))
		return
	}
	stats.Add(stats.DataOut, int64(len(h.buf))+1)
	h.w.Write(h.buf)
	h.w.WriteString("\n")
	h.lst = e.Time
	if h.fst == 0 {
		h.fst = e.Time
	}
}

func (h *textDumpHandler) OnClose() {
	h.w.Flush()
	h.out.Close()
	path := h.out.Name()
	if h.fst == 0 {
		os.Remove(path)
	} else {
		finalPath := filepath.Join(filepath.Dir(path), fmt.Sprintf("%d.%d.%s.tsv", h.fst, h.lst, h.conn.HashStr()))
		os.Rename(path, finalPath)
		if h.collect != nil {
			h.collect(&textFileInfo{id: h.conn.HashStr(), path: finalPath, fst: h.fst, lst: h.lst})
		}
	}
}

func NewTextPlayCommand() *cobra.Command {
	var (
		agents         []string
		options        playOptions
		targetDSN      string
		reportInterval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "play",
		Short: "PlayLocal mysql events from text files",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				done = make(chan struct{})
				err  error
				ctl  *playControl
			)
			ctl, err = newPlayControl(options, args[0], targetDSN)
			if err != nil {
				return err
			}

			fields := make([]zap.Field, 0, 10)
			loadFields := func() {
				metrics := stats.Dump()
				fields = fields[:0]
				for _, name := range []string{
					stats.Connections, stats.ConnRunning, stats.ConnWaiting,
					stats.Queries, stats.StmtExecutes, stats.StmtPrepares,
					stats.FailedQueries, stats.FailedStmtExecutes, stats.FailedStmtPrepares,
				} {
					fields = append(fields, zap.Int64(name, metrics[name]))
				}
				if lagging := stats.GetLagging(); lagging > 0 {
					fields = append(fields, zap.Duration("lagging", stats.GetLagging()))
				}
			}

			go func() {
				ticker := time.NewTicker(reportInterval)
				defer ticker.Stop()
				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						loadFields()
						ctl.log.Info("stats", fields...)
					}
				}
			}()

			ctl.Play(context.Background(), agents)
			close(done)
			loadFields()
			ctl.log.Info("done", fields...)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&agents, "agents", []string{}, "agents list")
	cmd.Flags().StringVar(&targetDSN, "target-dsn", "", "target dsn")
	cmd.Flags().Float64Var(&options.Speed, "speed", 1, "speed ratio")
	cmd.Flags().Int64Var(&options.Split, "split", 1, "split a session into multiple parts and replay them concurrently")
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "dry run mode (just print events)")
	cmd.Flags().IntVar(&options.MaxLineSize, "max-line-size", 16777216, "max line size")
	cmd.Flags().DurationVar(&options.QueryTimeout, "query-timeout", time.Minute, "timeout for a single query")
	cmd.Flags().DurationVar(&reportInterval, "report-interval", 5*time.Second, "report interval")
	return cmd
}

type playOptions struct {
	DryRun       bool
	Speed        float64
	Split        int64
	MaxLineSize  int
	QueryTimeout time.Duration
	MySQLConfig  *mysql.Config
}

type playControl struct {
	playOptions

	log  *zap.Logger
	jobs []*PlayJob
}

func newPlayControl(opts playOptions, input string, target string) (*playControl, error) {
	files, err := ioutil.ReadDir(input)
	if err != nil {
		return nil, err
	}
	ctl := &playControl{playOptions: opts, log: zap.L()}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		job, err := NewPlayJobFromFile(filepath.Join(input, file.Name()))
		if err != nil {
			ctl.log.Info("skip input file", zap.String("reason", err.Error()))
			continue
		}
		job.DSN = target
		job.MaxLineSize = int64(ctl.MaxLineSize)
		job.QueryTimeout = int64(ctl.QueryTimeout / time.Millisecond)
		job.Split = ctl.Split
		job.Speed = ctl.Speed
		ctl.jobs = append(ctl.jobs, job)
	}
	sort.Slice(ctl.jobs, func(i, j int) bool { return ctl.jobs[i].From < ctl.jobs[j].From })
	if !ctl.DryRun {
		ctl.MySQLConfig, err = mysql.ParseDSN(target)
		if err != nil {
			return nil, err
		}
	}
	return ctl, nil
}

func (pc *playControl) PlayLocal(ctx context.Context) {
	playStartTime := time.Now().UnixNano() / int64(time.Millisecond)
	eventStartTime := int64(0)
	if len(pc.jobs) > 0 {
		eventStartTime = pc.jobs[0].From
	}
	var wg sync.WaitGroup
	for _, job := range pc.jobs {
		var d time.Duration
		if pc.Speed > 0 {
			d = time.Duration((float64(job.From-eventStartTime)/pc.Speed+float64(playStartTime))*float64(time.Millisecond) - float64(time.Now().UnixNano()))
		}
		if d > 0 {
			<-time.After(d)
		}
		job.Start(ctx, &wg)
	}
	wg.Wait()
	return
}

func (pc *playControl) PlayRemote(ctx context.Context, agents []string) {
	playStartTime := time.Now().UnixNano() / int64(time.Millisecond)
	eventStartTime := int64(0)
	if len(pc.jobs) > 0 {
		eventStartTime = pc.jobs[0].From
	}
	allSubmitted := int32(0)
	name := fmt.Sprintf("job-%d-%d", playStartTime, rand.Int63())

	go func() {
		defer atomic.StoreInt32(&allSubmitted, 1)
		for i, job := range pc.jobs {
			var d time.Duration
			if pc.Speed > 0 {
				d = time.Duration((float64(job.From-eventStartTime)/pc.Speed+float64(playStartTime))*float64(time.Millisecond) - float64(time.Now().UnixNano()))
			}
			if d > 0 {
				<-time.After(d)
			}
			agent := agents[i%len(agents)]
			req, err := job.ToRequest(fmt.Sprintf("%s/%s", agent, name))
			if err != nil {
				pc.log.Error("build remote request", zap.Error(err))
				continue
			}
			go func(name string) {
				logger := pc.log.With(zap.String("job", name), zap.String("url", req.URL.String()))
				logger.Info("submit job")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					logger.Error("send remote request", zap.Error(err))
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					fields := []zap.Field{zap.Int("status", resp.StatusCode)}
					if msg, err := ioutil.ReadAll(resp.Body); err == nil {
						fields = append(fields, zap.String("body", string(msg)))
					}
					logger.Error("unexpected response", fields...)
				}
			}(fmt.Sprintf("%d.%d.%016x", job.From, job.To, job.ID))
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	for {
		<-ticker.C
		var (
			total    = 0
			finished = 0
			lagging  = .0
			counters = map[string]int64{}
		)
		for _, agent := range agents {
			resp, err := http.Get(fmt.Sprintf("%s/%s", agent, name))
			if err != nil {
				pc.log.Error("query job status", zap.String("agent", agent), zap.Error(err))
				continue
			}
			if resp.StatusCode != http.StatusOK {
				fields := []zap.Field{zap.String("agent", agent), zap.Int("status", resp.StatusCode)}
				if msg, err := ioutil.ReadAll(resp.Body); err == nil {
					fields = append(fields, zap.String("body", string(msg)))
				}
				pc.log.Error("unexpected response", fields...)
				continue
			}
			var status playJobStatus
			err = json.NewDecoder(resp.Body).Decode(&status)
			if err != nil {
				pc.log.Error("decode response", zap.String("agent", agent), zap.Error(err))
				continue
			}
			total += status.Total
			finished += status.Finished
			if lagging < status.Lagging {
				lagging = status.Lagging
			}
			for _, name := range []string{
				stats.Connections, stats.ConnRunning, stats.ConnWaiting,
				stats.Queries, stats.StmtExecutes, stats.StmtPrepares,
				stats.FailedQueries, stats.FailedStmtExecutes, stats.FailedStmtPrepares,
			} {
				counters[name] += status.Stats[name]
			}
		}
		stats.SetLagging(0, time.Duration(lagging*float64(time.Second)))
		for _, name := range []string{
			stats.Connections, stats.ConnRunning, stats.ConnWaiting,
			stats.Queries, stats.StmtExecutes, stats.StmtPrepares,
			stats.FailedQueries, stats.FailedStmtExecutes, stats.FailedStmtPrepares,
		} {
			stats.Add(name, counters[name]-stats.Get(name))
		}
		if atomic.LoadInt32(&allSubmitted) > 0 && total == finished {
			break
		}
		//pc.log.Info("progress", zap.Int("total", total), zap.Int("finished", finished))
	}
	ticker.Stop()
	stats.SetLagging(0, 0)
	return
}

func (pc *playControl) Play(ctx context.Context, agents []string) {
	if len(agents) == 0 {
		pc.PlayLocal(ctx)
	} else {
		pc.PlayRemote(ctx, agents)
	}
}

func NewTextCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "text",
		Short: "Text format utilities",
	}
	cmd.AddCommand(NewTextDumpCommand())
	cmd.AddCommand(NewTextPlayCommand())
	cmd.AddCommand(NewTextAgentCommand())
	return cmd
}

type playJobStatus struct {
	Total    int              `json:"total"`
	Finished int              `json:"finished"`
	Lagging  float64          `json:"lagging"`
	Stats    map[string]int64 `json:"stats"`
}

type playJobItem struct {
	item     *PlayJob
	form     *multipart.Form
	finished uint32
}

func (job *playJobItem) run() {
	defer func() {
		atomic.StoreUint32(&job.finished, 1)
		job.form.RemoveAll()
	}()
	var wg sync.WaitGroup
	job.item.Start(context.Background(), &wg)
	wg.Wait()
}

type playStore struct {
	jobs map[string][]*playJobItem
	lock sync.Mutex
}

func (store *playStore) append(key string, item *playJobItem) {
	store.lock.Lock()
	store.jobs[key] = append(store.jobs[key], item)
	store.lock.Unlock()
}

func (store *playStore) status(key string) *playJobStatus {
	var status playJobStatus
	store.lock.Lock()
	status.Total = len(store.jobs[key])
	for _, item := range store.jobs[key] {
		if atomic.LoadUint32(&item.finished) == 1 {
			status.Finished += 1
		}
	}
	store.lock.Unlock()
	status.Stats = stats.Dump()
	status.Lagging = float64(stats.GetLagging()) / float64(time.Second)
	return &status
}

func newTaskStore() *playStore {
	return &playStore{jobs: make(map[string][]*playJobItem)}
}

func (store *playStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		store.handleJobStatusQuery(w, r)
	} else if r.Method == http.MethodPost {
		store.handleTaskSubmission(w, r)
	} else {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (store *playStore) handleTaskSubmission(w http.ResponseWriter, r *http.Request) {
	item, form, err := NewPlayJobFromRequest(r)
	if err != nil {
		if form != nil {
			form.RemoveAll()
		}
		zap.L().Error("build job from request", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	job := playJobItem{item: item, form: form}
	go job.run()
	store.append(r.URL.Path, &job)
	w.WriteHeader(http.StatusOK)
}

func (store *playStore) handleJobStatusQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(store.status(r.URL.Path))
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
