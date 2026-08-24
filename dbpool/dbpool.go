// Package dbpool makes database connection-pool exhaustion visible.
//
// # Why this exists
//
// Every aikey service bounds its pool (SetMaxOpenConns, default 20). That bound
// is deliberate: an unbounded pool turns a burst of concurrent queries into one
// physical PostgreSQL connection each, and during the 2026-08-19 capacity-ladder
// incident that blew through PostgreSQL's max_connections and took every other
// client down with it. The bound was documented as "queuing on a bounded pool
// degrades gracefully".
//
// Queuing does degrade gracefully. It also degrades INVISIBLY — and that half
// was never instrumented. When all connections are busy, database/sql blocks the
// next caller inside the pool with no callback, no log and no metric. The HTTP
// handler waiting on it never writes response headers, so from the outside the
// server looks like it accepted the TCP connection and then went silent.
//
// That is exactly the shape observed on 2026-08-24, when the desktop team-usage
// page failed with 502s and the gateway logged:
//
//	conn_reused=false tcp_connect_ms=10 elapsed_ms=15011
//
// TCP connected in 10ms; no response header in 15 seconds. Pool exhaustion is
// the leading candidate for that shape, and nothing in the system could confirm
// or refute it — there was no signal to read.
//
// # What it does NOT do
//
// database/sql exposes no hook for "a caller is now blocked acquiring a
// connection", so this package cannot log per blocked acquire. It samples
// db.Stats() and reports on the DELTA, which means:
//
//   - a saturation shorter than one sample interval can be missed;
//   - the report says "connections were exhausted during this window", not
//     "request X waited".
//
// Request-level attribution needs a context deadline on the query path, which is
// a behaviour change (a request that would have queued and eventually succeeded
// starts failing instead) and is deliberately NOT part of this package.
package dbpool

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"
)

// Event names and error codes. Declared here because this package is the
// emitter and is shared by every service that owns a pool.
const (
	EventPoolExhausted  = "db.pool.exhausted"
	EventPoolSaturating = "db.pool.saturating"
	EventPoolRecovered  = "db.pool.recovered"

	ErrCodePoolExhausted = "SYS_DB_POOL_EXHAUSTED"
)

const (
	// DefaultInterval: short enough that a stall long enough to time out an HTTP
	// caller (15s at the gateway) cannot pass unsampled, long enough to be free.
	DefaultInterval = 10 * time.Second

	// saturatingRatio reports the RAMP. Logging only full exhaustion shows the
	// cliff and never the approach, so a pool creeping to its limit over an hour
	// would look like it failed out of nowhere.
	saturatingRatio = 0.8
)

// Status is the pool's current condition, suitable for a health signal.
type Status struct {
	Level  string // "OK" | "WARN" | "CRIT"
	InUse  int
	MaxOpen int
	// WaitCountDelta / WaitDurationMS are for the LAST observed window, not
	// cumulative: a cumulative counter cannot answer "is it happening now".
	WaitCountDelta int64
	WaitDurationMS int64
}

// Monitor samples one *sql.DB and reports saturation.
type Monitor struct {
	name   string
	db     *sql.DB
	logger *slog.Logger

	mu        sync.Mutex
	last      sql.DBStats
	status    Status
	exhausted bool // for edge-triggered recovery reporting
}

// New returns a Monitor for db. name identifies the pool in logs when a service
// owns more than one.
func New(name string, db *sql.DB, logger *slog.Logger) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{name: name, db: db, logger: logger,
		status: Status{Level: "OK", MaxOpen: db.Stats().MaxOpenConnections}}
}

// Run samples until ctx is done. Safe to call in a goroutine at startup.
func (m *Monitor) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	m.mu.Lock()
	m.last = m.db.Stats()
	m.mu.Unlock()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.sample()
		}
	}
}

// Status returns the last observed condition. Never blocks on the database, so
// a health endpoint stays answerable even while the pool is fully exhausted —
// the one moment it matters most.
func (m *Monitor) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Monitor) sample() {
	s := m.db.Stats()

	m.mu.Lock()
	waitDelta := s.WaitCount - m.last.WaitCount
	durDelta := s.WaitDuration - m.last.WaitDuration
	m.last = s
	wasExhausted := m.exhausted
	m.mu.Unlock()

	if waitDelta < 0 {
		waitDelta = 0 // counters reset (pool rebuilt)
	}
	if durDelta < 0 {
		durDelta = 0
	}

	st := Status{
		Level: "OK", InUse: s.InUse, MaxOpen: s.MaxOpenConnections,
		WaitCountDelta: waitDelta, WaitDurationMS: durDelta.Milliseconds(),
	}

	switch {
	// Callers actually queued AND every connection is busy: this is exhaustion,
	// not merely a busy pool. Both conditions are required — a pool can sit at
	// max with nobody waiting, which is healthy saturation, not a stall.
	case waitDelta > 0 && s.MaxOpenConnections > 0 && s.InUse >= s.MaxOpenConnections:
		st.Level = "CRIT"
		avg := int64(0)
		if waitDelta > 0 {
			avg = durDelta.Milliseconds() / waitDelta
		}
		m.logger.Error("database connection pool exhausted, callers are queuing for a connection",
			slog.String("event.name", EventPoolExhausted),
			slog.String("error.code", ErrCodePoolExhausted),
			slog.String("pool", m.name),
			slog.Int("in_use", s.InUse),
			slog.Int("max_open", s.MaxOpenConnections),
			slog.Int64("waited_since_last_sample", waitDelta),
			slog.Int64("wait_total_ms", durDelta.Milliseconds()),
			slog.Int64("wait_avg_ms", avg),
			// A request blocked here writes no response headers, so upstream
			// callers see a silent connection rather than an error. Say it in the
			// line: whoever reads this is probably holding a 502 report.
			slog.String("impact", "requests block before writing response headers; callers observe a silent connection, not an error"),
			slog.String("remedy", "raise AIKEY_DB_MAX_OPEN_CONNS, or find the slow query holding connections"))

	case s.MaxOpenConnections > 0 && float64(s.InUse) >= saturatingRatio*float64(s.MaxOpenConnections):
		st.Level = "WARN"
		m.logger.Warn("database connection pool approaching its limit",
			slog.String("event.name", EventPoolSaturating),
			slog.String("pool", m.name),
			slog.Int("in_use", s.InUse),
			slog.Int("max_open", s.MaxOpenConnections),
			slog.Int64("waited_since_last_sample", waitDelta))
	}

	nowExhausted := st.Level == "CRIT"
	m.mu.Lock()
	m.status = st
	m.exhausted = nowExhausted
	m.mu.Unlock()

	// Edge-triggered recovery: without it the log shows an outage starting and
	// never ending, and nobody can tell how long it lasted.
	if wasExhausted && !nowExhausted {
		m.logger.Info("database connection pool recovered",
			slog.String("event.name", EventPoolRecovered),
			slog.String("pool", m.name),
			slog.Int("in_use", s.InUse),
			slog.Int("max_open", s.MaxOpenConnections))
	}
}
