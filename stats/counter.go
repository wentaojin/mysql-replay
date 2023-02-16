package stats

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	Packets      = "packets"
	Queries      = "queries"
	Streams      = "streams"
	Connections  = "connections"
	ConnWaiting  = "conn.waiting"
	ConnRunning  = "conn.running"
	StmtExecutes = "stmt.executes"
	StmtPrepares = "stmt.prepares"
	DataIn       = "data.in"
	DataOut      = "data.out"

	ComQueryTotal   = "com.query.total"
	ComQueryError   = "com.query.error"
	ComPrepareTotal = "com.prepare.total"
	ComPrepareError = "com.prepare.error"
	ComExecuteTotal = "com.execute.total"
	ComExecuteError = "com.execute.error"

	SkippedQueries      = "skipped.queries"
	SkippedStmtExecutes = "skipped.stmt.prepares"
	SkippedStmtPrepares = "skipped.stmt.executes"

	FailedQueries      = "err.queries"
	FailedStmtExecutes = "err.stmt.executes"
	FailedStmtPrepares = "err.stmt.prepares"
)

var (
	nPackets      int64
	nQueries      int64
	nStreams      int64
	nConns        int64
	nStmtExecutes int64
	nStmtPrepares int64
	nDataIn       int64
	nDataOut      int64

	nComQueryTotal   int64
	nComQueryError   int64
	nComPrepareTotal int64
	nComPrepareError int64
	nComExecuteTotal int64
	nComExecuteError int64

	nSkippedQueries      int64
	nSkippedStmtExecutes int64
	nSkippedStmtPrepares int64

	nErrQueries      int64
	nErrStmtExecutes int64
	nErrStmtPrepares int64

	nRunningConns int64
	nWaitingConns int64

	laggings sync.Map

	metrics = []string{
		Packets, Queries, StmtExecutes, StmtPrepares, Streams, Connections,
		ComQueryTotal, ComPrepareTotal, ComExecuteTotal,
		ComQueryError, ComPrepareError, ComExecuteError,
		SkippedQueries, SkippedStmtExecutes, SkippedStmtPrepares,
		FailedQueries, FailedStmtExecutes, FailedStmtPrepares,
		ConnWaiting, ConnRunning,
	}
	others = make(map[string]int64)
	lock   sync.RWMutex
)

func Add(name string, delta int64) int64 {
	switch name {
	case Packets:
		return atomic.AddInt64(&nPackets, delta)
	case DataIn:
		return atomic.AddInt64(&nDataIn, delta)
	case DataOut:
		return atomic.AddInt64(&nDataOut, delta)
	case ConnRunning:
		return atomic.AddInt64(&nRunningConns, delta)
	case ConnWaiting:
		return atomic.AddInt64(&nWaitingConns, delta)
	case Queries:
		return atomic.AddInt64(&nQueries, delta)
	case StmtExecutes:
		return atomic.AddInt64(&nStmtExecutes, delta)
	case StmtPrepares:
		return atomic.AddInt64(&nStmtPrepares, delta)
	case Streams:
		return atomic.AddInt64(&nStreams, delta)
	case Connections:
		return atomic.AddInt64(&nConns, delta)
	case ComQueryTotal:
		return atomic.AddInt64(&nComQueryTotal, delta)
	case ComQueryError:
		return atomic.AddInt64(&nComQueryError, delta)
	case ComExecuteTotal:
		return atomic.AddInt64(&nComExecuteTotal, delta)
	case ComExecuteError:
		return atomic.AddInt64(&nComExecuteError, delta)
	case ComPrepareTotal:
		return atomic.AddInt64(&nComPrepareTotal, delta)
	case ComPrepareError:
		return atomic.AddInt64(&nComPrepareError, delta)
	case SkippedQueries:
		return atomic.AddInt64(&nSkippedQueries, delta)
	case SkippedStmtExecutes:
		return atomic.AddInt64(&nSkippedStmtPrepares, delta)
	case SkippedStmtPrepares:
		return atomic.AddInt64(&nSkippedStmtExecutes, delta)
	case FailedQueries:
		return atomic.AddInt64(&nErrQueries, delta)
	case FailedStmtExecutes:
		return atomic.AddInt64(&nErrStmtExecutes, delta)
	case FailedStmtPrepares:
		return atomic.AddInt64(&nErrStmtPrepares, delta)
	default:
		lock.Lock()
		defer lock.Unlock()
		others[name] += delta
		return others[name]
	}
}

func Get(name string) int64 {
	switch name {
	case Packets:
		return atomic.LoadInt64(&nPackets)
	case DataIn:
		return atomic.LoadInt64(&nDataIn)
	case DataOut:
		return atomic.LoadInt64(&nDataOut)
	case ConnRunning:
		return atomic.LoadInt64(&nRunningConns)
	case ConnWaiting:
		return atomic.LoadInt64(&nWaitingConns)
	case Queries:
		return atomic.LoadInt64(&nQueries)
	case StmtExecutes:
		return atomic.LoadInt64(&nStmtExecutes)
	case StmtPrepares:
		return atomic.LoadInt64(&nStmtPrepares)
	case Streams:
		return atomic.LoadInt64(&nStreams)
	case Connections:
		return atomic.LoadInt64(&nConns)
	case ComQueryTotal:
		return atomic.LoadInt64(&nComQueryTotal)
	case ComQueryError:
		return atomic.LoadInt64(&nComQueryError)
	case ComExecuteTotal:
		return atomic.LoadInt64(&nComExecuteTotal)
	case ComExecuteError:
		return atomic.LoadInt64(&nComExecuteError)
	case ComPrepareTotal:
		return atomic.LoadInt64(&nComPrepareTotal)
	case ComPrepareError:
		return atomic.LoadInt64(&nComPrepareError)
	case SkippedQueries:
		return atomic.LoadInt64(&nSkippedQueries)
	case SkippedStmtExecutes:
		return atomic.LoadInt64(&nSkippedStmtPrepares)
	case SkippedStmtPrepares:
		return atomic.LoadInt64(&nSkippedStmtExecutes)
	case FailedQueries:
		return atomic.LoadInt64(&nErrQueries)
	case FailedStmtExecutes:
		return atomic.LoadInt64(&nErrStmtExecutes)
	case FailedStmtPrepares:
		return atomic.LoadInt64(&nErrStmtPrepares)
	default:
		lock.RLock()
		defer lock.RUnlock()
		return others[name]
	}
}

func Dump() map[string]int64 {
	out := make(map[string]int64, len(metrics)+len(others))
	for _, name := range metrics {
		out[name] = Get(name)
	}
	lock.RLock()
	for k, v := range others {
		out[k] = v
	}
	lock.RUnlock()
	return out
}

func SetLagging(c uint64, d time.Duration) {
	if d <= 0 {
		laggings.Delete(c)
	} else {
		laggings.Store(c, d)
	}
}

func GetLagging() time.Duration {
	var d time.Duration
	laggings.Range(func(key, value interface{}) bool {
		if dd, ok := value.(time.Duration); ok && dd > d {
			d = dd
		}
		return true
	})
	return d
}
