package session

// Experimental, opt-in server evidence. It never changes deadlines, framing or
// scheduling. Registry and per-session structures have fixed capacity; a stale
// generation cannot write evidence into a different session's reused slot.
import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const evidenceSessions = 32
const evidenceWaiters = 32
const evidenceSlowEvents = 32
const evidenceSlowThreshold = 100 * time.Millisecond
const evidenceStageCount = 6
const (
	stageWriterWait = iota
	stageWriterOwned
	stageTLSWrite
	stageReadHeader
	stageReadBody
	stagePipeWrite
)

var evidenceStageNames = [evidenceStageCount]string{"writer_wait", "writer_owned", "tls_write", "read_header", "read_body", "pipe_write"}

type stageMetric struct {
	Count   uint64  `json:"count"`
	TotalMS float64 `json:"total_ms"`
	MaxMS   float64 `json:"max_ms"`
	Errors  uint64  `json:"errors"`
	Slow    uint64  `json:"slow_count"`
}
type stageActive struct {
	Stage string  `json:"stage"`
	Frame string  `json:"frame_class"`
	Bytes int     `json:"bytes"`
	AgeMS float64 `json:"age_ms"`
}
type stageSnapshot struct {
	Session                string                          `json:"session"`
	SocketCookie           *string                         `json:"socket_cookie"` // private collector join only
	Status                 string                          `json:"status"`
	Known                  bool                            `json:"inflight_known"`
	CapturedAt             string                          `json:"captured_at"`
	AgeMS                  float64                         `json:"session_age_ms"`
	Pending                int                             `json:"pending_writers"`
	TrackedWaiters         int                             `json:"tracked_waiters"`
	WaiterCoverageComplete bool                            `json:"writer_wait_coverage_complete"`
	WaiterOverflow         uint64                          `json:"waiter_overflow_total"`
	Active                 []stageActive                   `json:"active"`
	Metrics                [evidenceStageCount]stageMetric `json:"metrics"`
}
type stageSlowEvent struct {
	completed   time.Time // monotonic ordering key; never exported
	StartedAt   string    `json:"started_at"`
	CompletedAt string    `json:"completed_at"`
	Session     string    `json:"session"`
	Stage       string    `json:"stage"`
	Frame       string    `json:"frame_class"`
	Bytes       int       `json:"bytes"`
	DurationMS  float64   `json:"duration_ms"`
	Failed      bool      `json:"failed"`
}
type stageBatch struct {
	Schema             int                                        `json:"schema"`
	Kind               string                                     `json:"kind"`
	EvidenceEpoch      string                                     `json:"evidence_epoch"`
	Sequence           uint64                                     `json:"sequence"`
	CaptureStarted     string                                     `json:"capture_started"`
	CaptureEnded       string                                     `json:"capture_ended"`
	Time               string                                     `json:"time"`
	ExportAgeMS        float64                                    `json:"export_age_ms"`
	Captured           time.Time                                  `json:"-"`
	PayloadLimited     bool                                       `json:"payload_limited"`
	OmittedSessions    int                                        `json:"omitted_sessions"`
	OmittedSlow        int                                        `json:"omitted_slow_events"`
	StageNames         [evidenceStageCount]string                 `json:"metric_stage_names"`
	Admission          string                                     `json:"admission_policy"`
	Live               int64                                      `json:"live_authenticated_sessions"`
	Tracked            int                                        `json:"tracked_live_sessions"`
	Untracked          int64                                      `json:"untracked_live_sessions"`
	Evicted            uint64                                     `json:"evicted_sessions_total"`
	LostCompletions    uint64                                     `json:"lost_completion_total"`
	LostBatches        uint64                                     `json:"lost_batch_total"`
	LostSlow           uint64                                     `json:"lost_slow_event_total"`
	LostTerminal       uint64                                     `json:"lost_terminal_record_total"`
	Sessions           []stageSnapshot                            `json:"sessions"`
	SlowEvents         []stageSlowEvent                           `json:"slow_events"`
	SlowEventPolicy    string                                     `json:"slow_event_policy"`
	SlowQueueStats     [evidenceStageCount]stageSlowQueueCounters `json:"slow_queue_counters"`
	OmittedSlowByClass [evidenceStageCount]int                    `json:"omitted_slow_events_by_class"`
}
type stageWaiter struct {
	used    bool
	started time.Time
	frame   string
	bytes   int
}
type stageSlot struct {
	mu         sync.Mutex
	generation uint64
	session    string
	cookie     *string
	created    time.Time
	live       bool
	pending    int
	overflow   uint64
	waiters    [evidenceWaiters]stageWaiter
	owner      stageWaiter
	ownerTLS   time.Time
	read       stageWaiter
	readStage  int
	metrics    [evidenceStageCount]stageMetric
}
type stageHub struct {
	mu              sync.Mutex // admission/terminal ring only; never taken by normal DATA ops
	slots           [evidenceSessions]stageSlot
	next            int
	generation      uint64
	nonce           string
	live            atomic.Int64
	evicted         atomic.Uint64
	lostCompletions atomic.Uint64
	lostBatches     atomic.Uint64
	lostSlow        atomic.Uint64
	lostTerminal    atomic.Uint64
	sequence        atomic.Uint64
	failedExports   atomic.Uint64
	latest          atomic.Pointer[stagePublication]
	terminal        [evidenceSessions]stageSnapshot
	terminalN       int
	slow            [evidenceStageCount]stageSlowQueue
	batches         chan stageBatch
	stop            chan struct{}
	stopOnce        sync.Once
}
type stageHandle struct {
	hub        *stageHub
	slot       int
	generation uint64
	once       sync.Once
}
type stageWriteOp struct {
	valid             bool
	waitSlot          int
	started, acquired time.Time
	frame             string
	bytes             int
}
type stageReadOp struct {
	valid   bool
	started time.Time
	stage   int
	frame   string
	bytes   int
}

var serverStageOnce sync.Once
var serverStageHub atomic.Pointer[stageHub]

func newStageHub() *stageHub {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil
	}
	h := &stageHub{nonce: hex.EncodeToString(nonce[:]), batches: make(chan stageBatch, 1), stop: make(chan struct{})}
	for i, capacity := range evidenceSlowClassCapacity {
		h.slow[i].events = make(chan stageSlowEvent, capacity)
	}
	return h
}

// EnableServerStageEvidence must be called once, before Run, by an authenticated
// listener. Client sessions refuse it. nil cookies explicitly mean unjoinable.
func (s *Session) EnableServerStageEvidence(cookie *string) bool {
	if s.isClient || s.IsClosed() || s.evidence != nil {
		return false
	}
	serverStageOnce.Do(func() {
		h := newStageHub()
		if h != nil {
			serverStageHub.Store(h)
			h.start(h.publish)
		}
	})
	h := serverStageHub.Load()
	if h == nil {
		return false
	}
	s.evidence = h.attach(cookie)
	return true
}
func (h *stageHub) start(sink func(stageBatch)) {
	go func() {
		for {
			select {
			case <-h.stop:
				return
			case b := <-h.batches:
				b.ExportAgeMS = float64(time.Since(b.Captured)) / float64(time.Millisecond)
				sink(b)
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-h.stop:
				return
			case now := <-ticker.C:
				b := h.collect(now)
				select {
				case h.batches <- b:
				default:
					h.lostBatches.Add(1)
				}
			}
		}
	}()
}
func (h *stageHub) close() { h.stopOnce.Do(func() { close(h.stop) }) }
func (h *stageHub) attach(cookie *string) *stageHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	// The selected slot stays locked from eligibility check through generation
	// replacement. A DATA operation cannot become a protected slow writer in
	// the gap between those actions. Admission never waits for network progress.
	index, slot := h.admissionSlotLocked()
	h.next = (index + 1) % evidenceSessions
	defer slot.mu.Unlock()
	if slot.live {
		h.evicted.Add(1)
		h.addTerminalLocked(slot.snapshotLocked(time.Now(), "evicted", false))
	}
	h.generation++
	// Do not assign over the mutex. Old handles retain only (slot,generation).
	slot.generation = h.generation
	slot.session = h.nonce + "-" + hexUint(h.generation)
	slot.cookie = nil
	if cookie != nil && len(*cookie) <= 16 {
		if value, err := strconv.ParseUint(*cookie, 16, 64); err == nil && value != 0 {
			canonical := hexUint(value)
			slot.cookie = &canonical
		}
	}
	slot.created = time.Now()
	slot.live = true
	slot.pending = 0
	slot.overflow = 0
	slot.waiters = [evidenceWaiters]stageWaiter{}
	slot.owner = stageWaiter{}
	slot.ownerTLS = time.Time{}
	slot.read = stageWaiter{}
	slot.metrics = [evidenceStageCount]stageMetric{}
	h.live.Add(1)
	return &stageHandle{hub: h, slot: index, generation: h.generation}
}
func hexUint(v uint64) string {
	const digits = "0123456789abcdef"
	var b [16]byte
	i := len(b)
	for {
		i--
		b[i] = digits[v&15]
		v >>= 4
		if v == 0 {
			return string(b[i:])
		}
	}
}
func (h *stageHub) addTerminalLocked(s stageSnapshot) {
	if h.terminalN == len(h.terminal) {
		h.lostTerminal.Add(1)
		return
	}
	h.terminal[h.terminalN] = s
	h.terminalN++
}
func (e *stageHandle) close() {
	if e == nil {
		return
	}
	e.once.Do(func() {
		h := e.hub
		h.mu.Lock()
		defer h.mu.Unlock()
		h.live.Add(-1)
		slot := &h.slots[e.slot]
		slot.mu.Lock()
		defer slot.mu.Unlock()
		if slot.generation != e.generation || !slot.live {
			return
		}
		h.addTerminalLocked(slot.snapshotLocked(time.Now(), "closed", false))
		slot.live = false
	})
}
func (e *stageHandle) lock() (*stageSlot, bool) {
	if e == nil {
		return nil, false
	}
	s := &e.hub.slots[e.slot]
	s.mu.Lock()
	if s.generation != e.generation || !s.live {
		s.mu.Unlock()
		return nil, false
	}
	return s, true
}
func frameKind(command byte) string {
	switch command {
	case cmdPSH:
		return "data"
	case cmdSYNACK:
		return "synack"
	case cmdFIN:
		return "fin"
	case cmdSYN:
		return "syn"
	case cmdSettings, cmdServerSettings, cmdUpdatePaddingScheme:
		return "settings"
	case cmdHeartRequest, cmdHeartResponse:
		return "heartbeat"
	default:
		return "other"
	}
}
func (e *stageHandle) beginWrite(command byte, bytes int) stageWriteOp {
	if e == nil {
		return stageWriteOp{}
	}
	op := stageWriteOp{waitSlot: -1, started: time.Now(), frame: frameKind(command), bytes: bytes}
	s, ok := e.lock()
	if !ok {
		return op
	}
	defer s.mu.Unlock()
	op.valid = true
	s.pending++
	for i := range s.waiters {
		if !s.waiters[i].used {
			s.waiters[i] = stageWaiter{true, op.started, op.frame, bytes}
			op.waitSlot = i
			return op
		}
	}
	s.overflow++
	return op
}
func (s *stageSlot) record(stage int, start, end time.Time, err error) time.Duration {
	d := end.Sub(start)
	m := &s.metrics[stage]
	m.Count++
	ms := float64(d) / float64(time.Millisecond)
	m.TotalMS += ms
	if ms > m.MaxMS {
		m.MaxMS = ms
	}
	if err != nil {
		m.Errors++
	}
	if d >= evidenceSlowThreshold {
		m.Slow++
	}
	return d
}
func (e *stageHandle) slowEvent(s *stageSlot, stage int, frame string, bytes int, start, end time.Time, d time.Duration, err error) {
	if d < evidenceSlowThreshold {
		return
	}
	event := stageSlowEvent{completed: end, StartedAt: start.UTC().Format(time.RFC3339Nano), CompletedAt: end.UTC().Format(time.RFC3339Nano), Session: s.session, Stage: evidenceStageNames[stage], Frame: frame, Bytes: bytes, DurationMS: float64(d) / float64(time.Millisecond), Failed: err != nil}
	e.hub.enqueueSlow(stage, event)
}
func (e *stageHandle) acquire(op *stageWriteOp) {
	if e == nil || !op.valid {
		return
	}
	op.acquired = time.Now()
	s, ok := e.lock()
	if !ok {
		e.hub.lostCompletions.Add(1)
		op.valid = false
		return
	}
	defer s.mu.Unlock()
	d := s.record(stageWriterWait, op.started, op.acquired, nil)
	e.slowEvent(s, stageWriterWait, op.frame, op.bytes, op.started, op.acquired, d, nil)
	s.pending--
	if op.waitSlot >= 0 {
		s.waiters[op.waitSlot] = stageWaiter{}
	}
	s.owner = stageWaiter{true, op.acquired, op.frame, op.bytes}
}
func (e *stageHandle) finishWrite(op *stageWriteOp, err error) {
	if e == nil || !op.valid {
		return
	}
	ended := time.Now()
	s, ok := e.lock()
	if !ok {
		e.hub.lostCompletions.Add(1)
		return
	}
	defer s.mu.Unlock()
	d := s.record(stageWriterOwned, op.acquired, ended, err)
	e.slowEvent(s, stageWriterOwned, op.frame, op.bytes, op.acquired, ended, d, err)
	s.owner = stageWaiter{}
	s.ownerTLS = time.Time{}
}
func (e *stageHandle) write(op *stageWriteOp, conn net.Conn, b []byte) (int, error) {
	if e == nil || !op.valid {
		return conn.Write(b)
	}
	started := time.Now()
	if s, ok := e.lock(); ok {
		s.ownerTLS = started
		s.mu.Unlock()
	}
	n, err := conn.Write(b)
	ended := time.Now()
	if s, ok := e.lock(); ok {
		d := s.record(stageTLSWrite, started, ended, err)
		e.slowEvent(s, stageTLSWrite, op.frame, len(b), started, ended, d, err)
		s.ownerTLS = time.Time{}
		s.mu.Unlock()
	} else {
		e.hub.lostCompletions.Add(1)
	}
	return n, err
}
func (e *stageHandle) beginRead(stage int, command byte, bytes int) stageReadOp {
	if e == nil {
		return stageReadOp{}
	}
	op := stageReadOp{true, time.Now(), stage, frameKind(command), bytes}
	if stage == stageReadHeader {
		op.frame = "unknown"
	}
	s, ok := e.lock()
	if !ok {
		op.valid = false
		return op
	}
	s.read = stageWaiter{true, op.started, op.frame, bytes}
	s.readStage = stage
	s.mu.Unlock()
	return op
}
func (e *stageHandle) finishRead(op stageReadOp, err error) {
	if e == nil || !op.valid {
		return
	}
	ended := time.Now()
	s, ok := e.lock()
	if !ok {
		e.hub.lostCompletions.Add(1)
		return
	}
	d := s.record(op.stage, op.started, ended, err)
	e.slowEvent(s, op.stage, op.frame, op.bytes, op.started, ended, d, err)
	s.read = stageWaiter{}
	s.mu.Unlock()
}
func (s *Session) readEvidence(b []byte, stage int, command byte) (int, error) {
	if s.evidence == nil {
		return io.ReadFull(s.conn, b)
	}
	op := s.evidence.beginRead(stage, command, len(b))
	n, err := io.ReadFull(s.conn, b)
	s.evidence.finishRead(op, err)
	return n, err
}
func (s *Session) pipeEvidence(stream *Stream, b []byte) (int, error) {
	if s.evidence == nil {
		return stream.pipeW.Write(b)
	}
	op := s.evidence.beginRead(stagePipeWrite, cmdPSH, len(b))
	n, err := stream.pipeW.Write(b)
	s.evidence.finishRead(op, err)
	return n, err
}
func (s *stageSlot) snapshotLocked(now time.Time, status string, known bool) stageSnapshot {
	out := stageSnapshot{CapturedAt: now.UTC().Format(time.RFC3339Nano), Session: s.session, SocketCookie: s.cookie, Status: status, Known: known, AgeMS: float64(now.Sub(s.created)) / float64(time.Millisecond), Pending: s.pending, WaiterOverflow: s.overflow, Metrics: s.metrics}
	if !known {
		return out
	}
	out.Active = make([]stageActive, 0, 4)
	add := func(w stageWaiter, stage int) {
		out.Active = append(out.Active, stageActive{evidenceStageNames[stage], w.frame, w.bytes, float64(now.Sub(w.started)) / float64(time.Millisecond)})
	}
	var oldest stageWaiter
	for _, w := range s.waiters {
		if w.used {
			out.TrackedWaiters++
			if !oldest.used || w.started.Before(oldest.started) {
				oldest = w
			}
		}
	}
	if oldest.used {
		add(oldest, stageWriterWait)
	}
	out.WaiterCoverageComplete = out.Pending == out.TrackedWaiters
	if s.owner.used {
		add(s.owner, stageWriterOwned)
		if !s.ownerTLS.IsZero() {
			w := s.owner
			w.started = s.ownerTLS
			add(w, stageTLSWrite)
		}
	}
	if s.read.used {
		add(s.read, s.readStage)
	}
	return out
}
func (e *stageHandle) snapshot(_ time.Time) stageSnapshot {
	if e == nil {
		return stageSnapshot{Status: "disabled", Known: false}
	}
	s, ok := e.lock()
	if !ok {
		return stageSnapshot{Status: "untracked", Known: false}
	}
	defer s.mu.Unlock()
	return s.snapshotLocked(time.Now(), "active", true)
}
func (h *stageHub) collect(_ time.Time) (b stageBatch) {
	started := time.Now()
	defer func() {
		ended := time.Now()
		b.CaptureStarted = started.UTC().Format(time.RFC3339Nano)
		b.CaptureEnded = ended.UTC().Format(time.RFC3339Nano)
		b.Time = b.CaptureEnded
		b.Captured = ended
	}()
	b = stageBatch{Schema: 2, SlowEventPolicy: evidenceSlowPolicy, Kind: "diagnostic_not_failure", EvidenceEpoch: h.nonce, Sequence: h.sequence.Add(1), StageNames: evidenceStageNames, Admission: evidenceAdmissionPolicy, Evicted: h.evicted.Load(), LostCompletions: h.lostCompletions.Load(), LostBatches: h.lostBatches.Load(), LostSlow: h.lostSlow.Load(), LostTerminal: h.lostTerminal.Load()}
	h.mu.Lock()
	b.Live = h.live.Load()
	b.Sessions = append(b.Sessions, h.terminal[:h.terminalN]...)
	h.terminalN = 0
	for i := range h.slots {
		s := &h.slots[i]
		s.mu.Lock()
		if s.live {
			b.Tracked++
			b.Sessions = append(b.Sessions, s.snapshotLocked(time.Now(), "active", true))
		}
		s.mu.Unlock()
	}
	h.mu.Unlock()
	b.Untracked = b.Live - int64(b.Tracked)
	h.collectSlow(&b)
	return b
}
