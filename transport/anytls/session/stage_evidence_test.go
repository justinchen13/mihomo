package session

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	utls "github.com/metacubex/utls"
)

func testStageHub(t *testing.T) *stageHub {
	t.Helper()
	h := newStageHub()
	if h == nil {
		t.Fatal("random source")
	}
	t.Cleanup(h.close)
	return h
}
func stagePresent(s stageSnapshot, name string) bool {
	for _, v := range s.Active {
		if v.Stage == name {
			return true
		}
	}
	return false
}
func waitStage(t *testing.T, e *stageHandle, names ...string) stageSnapshot {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		s := e.snapshot(time.Now())
		all := true
		for _, n := range names {
			all = all && stagePresent(s, n)
		}
		if all {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("stages not reached: %v", names)
	return stageSnapshot{}
}

func TestStageEvidenceTLSWriterQueueAndCompletion(t *testing.T) {
	for _, version := range []uint16{utls.VersionTLS12, utls.VersionTLS13} {
		t.Run(hexUint(uint64(version)), func(t *testing.T) {
			writer, reader, wire := realTLSPair(t, version, true)
			var factory atomic.Pointer[padding.PaddingFactory]
			padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &factory)
			s := NewServerSession(writer, nil, &factory)
			h := testStageHub(t)
			s.evidence = h.attach(nil)
			defer s.Close()
			payload := bytes.Repeat([]byte{1, 3, 5, 7}, 1024)
			received := make(chan frameResult, 1)
			go func() { received <- readAcceptedFrames(reader, 2) }()
			wire.enabled.Store(true)
			dataDone, finDone := make(chan error, 1), make(chan error, 1)
			go func() { _, err := s.writeDataFrame(1, payload); dataDone <- err }()
			<-wire.entered
			go func() { _, err := s.writeControlFrame(newFrame(cmdFIN, 3)); finDone <- err }()
			snap := waitStage(t, s.evidence, "tls_write", "writer_wait")
			if snap.Pending != 1 || snap.TrackedWaiters != 1 {
				t.Fatal("queue coverage")
			}
			time.Sleep(120 * time.Millisecond)
			snap = waitStage(t, s.evidence, "tls_write", "writer_wait")
			for _, a := range snap.Active {
				if (a.Stage == "tls_write" || a.Stage == "writer_wait") && a.AgeMS < 100 {
					t.Fatal("in-flight age missing")
				}
			}
			awaitWrite(t, dataDone)
			awaitWrite(t, finDone)
			frames := <-received
			if frames.err != nil || len(frames.frames) != 2 || !bytes.Equal(frames.frames[0].payload, payload) || frames.frames[1].command != cmdFIN {
				t.Fatal("exact frame integrity")
			}
			snap = s.evidence.snapshot(time.Now())
			if len(snap.Active) != 0 || snap.Metrics[stageTLSWrite].MaxMS < 100 || snap.Metrics[stageWriterWait].MaxMS < 100 {
				t.Fatal("completed stall lost")
			}
			batch := h.collect(time.Now())
			if len(batch.SlowEvents) == 0 {
				t.Fatal("slow completion event lost below 10-second sample")
			}
			t.Log("verified TLS writer ownership, independent queued control age, full DATA/FIN and completed slow events")
		})
	}
}

func stageFrame(cmd byte, id uint32, data []byte) []byte {
	b := make([]byte, 7+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:], id)
	binary.BigEndian.PutUint16(b[5:], uint16(len(data)))
	copy(b[7:], data)
	return b
}
func TestStageEvidenceTLSReceiveWireVersusPipe(t *testing.T) {
	server, client, _ := realTLSPair(t, utls.VersionTLS13, true)
	h := testStageHub(t)
	var factory atomic.Pointer[padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &factory)
	streams := make(chan *Stream, 1)
	s := NewServerSession(server, func(st *Stream) { streams <- st }, &factory)
	s.evidence = h.attach(nil)
	defer s.Close()
	go s.Run()
	go io.Copy(io.Discard, client) // drain server SETTINGS/control only
	waitStage(t, s.evidence, "read_header")
	prefix := append(stageFrame(cmdSettings, 0, []byte("v=2\npadding-md5="+factory.Load().Md5)), stageFrame(cmdSYN, 1, nil)...)
	data := bytes.Repeat([]byte{0x5a}, 32)
	frame := stageFrame(cmdPSH, 1, data)
	if _, err := client.Write(append(prefix, frame[:23]...)); err != nil {
		t.Fatal(err)
	}
	st := <-streams
	waitStage(t, s.evidence, "read_body")
	if _, err := client.Write(frame[23:]); err != nil {
		t.Fatal(err)
	}
	waitStage(t, s.evidence, "pipe_write")
	time.Sleep(120 * time.Millisecond)
	snap := waitStage(t, s.evidence, "pipe_write")
	if stagePresent(snap, "read_body") || stagePresent(snap, "tls_write") {
		t.Fatal("wrong blocking classification")
	}
	got := make([]byte, len(data))
	if _, err := io.ReadFull(st, got); err != nil || !bytes.Equal(got, data) {
		t.Fatal("payload mismatch")
	}
	waitStage(t, s.evidence, "read_header")
	snap = s.evidence.snapshot(time.Now())
	if snap.Metrics[stagePipeWrite].MaxMS < 100 || snap.Metrics[stageReadBody].Count == 0 {
		t.Fatal("completed receive stage evidence missing")
	}
	s.Close()
	if snap = s.evidence.snapshot(time.Now()); snap.Known || snap.Status != "untracked" {
		t.Fatal("closed state cannot claim idle/known")
	}
	t.Log("incomplete TLS frame body differs from complete-frame application pipe wait; close marks evidence unknown")
}

func TestStageEvidenceCapacityRotationAndUnknown(t *testing.T) {
	h := testStageHub(t)
	handles := make([]*stageHandle, 0, evidenceSessions+1)
	first := h.attach(nil)
	handles = append(handles, first)
	oldOp := first.beginWrite(cmdPSH, 10)
	for i := 0; i < evidenceSessions; i++ {
		handles = append(handles, h.attach(nil))
	}
	if snap := first.snapshot(time.Now()); snap.Known || snap.Status != "untracked" {
		t.Fatal("evicted handle claimed knowledge")
	}
	first.acquire(&oldOp)
	if h.lostCompletions.Load() != 1 {
		t.Fatal("stale generation not counted")
	}
	b := h.collect(time.Now())
	if b.Live != 33 || b.Tracked != 32 || b.Untracked != 1 || b.Evicted != 1 {
		t.Fatal("bounded rotating coverage")
	}
	newest := handles[len(handles)-1]
	ops := make([]stageWriteOp, 33)
	for i := range ops {
		ops[i] = newest.beginWrite(cmdPSH, 1)
	}
	snap := newest.snapshot(time.Now())
	if snap.Pending != 33 || snap.TrackedWaiters != 32 || snap.WaiterCoverageComplete || snap.WaiterOverflow != 1 {
		t.Fatal("waiter overflow cannot be zero/complete")
	}
	for _, e := range handles {
		e.close()
	}
	b = h.collect(time.Now())
	if b.Live != 0 || b.Tracked != 0 {
		t.Fatal("live accounting")
	}
	for _, s := range b.Sessions {
		if s.Known || s.Active != nil {
			t.Fatal("terminal snapshot claims zero active")
		}
	}
}

func TestStageEvidenceSlowRingAndBlockedSinkAreBounded(t *testing.T) {
	h := testStageHub(t)
	e := h.attach(nil)
	for i := 0; i < evidenceSlowClassCapacity[stagePipeWrite]+5; i++ {
		op := e.beginRead(stagePipeWrite, cmdPSH, 4)
		op.started = time.Now().Add(-200 * time.Millisecond)
		e.finishRead(op, nil)
	}
	b := h.collect(time.Now())
	if len(b.SlowEvents) != evidenceSlowClassCapacity[stagePipeWrite] || b.LostSlow != 5 {
		t.Fatal("slow ring overflow accounting")
	}
	// A stalled external logger is never called by a proxy operation.
	entered, release := make(chan struct{}), make(chan struct{})
	var sinkOnce sync.Once
	h.start(func(stageBatch) { sinkOnce.Do(func() { close(entered) }); <-release })
	h.batches <- b
	<-entered
	h.batches <- b
	select {
	case h.batches <- b:
		t.Fatal("batch queue unbounded")
	default:
		h.lostBatches.Add(1)
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			op := e.beginWrite(cmdPSH, 1)
			e.acquire(&op)
			e.finishWrite(&op, nil)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("logging blocked proxy")
	}
	h.close()
	close(release)
	if h.lostBatches.Load() != 1 {
		t.Fatal("lost batch counter")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"remote_addr":`, `"password":`, `"user":`, `"target":`, `"payload":`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("forbidden field %s", forbidden)
		}
	}
}

func TestStageEvidenceDefaultOffAndClientRefusal(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := NewServerSession(a, nil, nil)
	if s.evidence != nil || s.evidence.snapshot(time.Now()).Known {
		t.Fatal("default should be disabled/unknown")
	}
	c := NewClientSession(b, nil)
	if c.EnableServerStageEvidence(nil) || c.evidence != nil {
		t.Fatal("client evidence forbidden")
	}
}

func TestStageEvidenceConcurrentSnapshotAndRotation(t *testing.T) {
	h := testStageHub(t)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				e := h.attach(nil)
				op := e.beginWrite(cmdPSH, 4)
				e.acquire(&op)
				e.finishWrite(&op, nil)
				e.close()
			}
		}()
	}
	for i := 0; i < 100; i++ {
		h.collect(time.Now())
	}
	wg.Wait()
	if h.collect(time.Now()).Live != 0 {
		t.Fatal("live leak")
	}
}

type stageDiscardConn struct{}

func (stageDiscardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (stageDiscardConn) Write(b []byte) (int, error)      { return len(b), nil }
func (stageDiscardConn) Close() error                     { return nil }
func (stageDiscardConn) LocalAddr() net.Addr              { return nil }
func (stageDiscardConn) RemoteAddr() net.Addr             { return nil }
func (stageDiscardConn) SetDeadline(time.Time) error      { return nil }
func (stageDiscardConn) SetReadDeadline(time.Time) error  { return nil }
func (stageDiscardConn) SetWriteDeadline(time.Time) error { return nil }
func BenchmarkStageEvidenceWrite(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		b.Run(name, func(b *testing.B) {
			s := NewServerSession(stageDiscardConn{}, nil, nil)
			if enabled {
				h := newStageHub()
				defer h.close()
				s.evidence = h.attach(nil)
			}
			payload := make([]byte, 16384)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.writeDataFrame(1, payload)
			}
		})
	}
}

func TestStageEvidenceDelayedTickerUsesActualCapture(t *testing.T) {
	h := testStageHub(t)
	e := h.attach(nil)
	op := e.beginWrite(cmdPSH, 10)
	before := time.Now()
	batch := h.collect(before.Add(-time.Hour))
	after := time.Now()
	start, err := time.Parse(time.RFC3339Nano, batch.CaptureStarted)
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC3339Nano, batch.CaptureEnded)
	if err != nil {
		t.Fatal(err)
	}
	if start.Before(before) || end.After(after) || end.Before(start) || batch.Time != batch.CaptureEnded {
		t.Fatal("scheduled tick mistaken for capture")
	}
	if len(batch.Sessions) != 1 {
		t.Fatal("snapshot")
	}
	row := batch.Sessions[0]
	at, err := time.Parse(time.RFC3339Nano, row.CapturedAt)
	if err != nil || at.Before(start) || at.After(end) {
		t.Fatal("slot capture time")
	}
	for _, stage := range row.Active {
		if stage.AgeMS < 0 {
			t.Fatal("negative in-flight age")
		}
	}
	e.acquire(&op)
	e.finishWrite(&op, nil)
	e.close()
}

func TestStageEvidenceExportQueueAge(t *testing.T) {
	h := testStageHub(t)
	e := h.attach(nil)
	defer e.close()
	entered, release := make(chan struct{}), make(chan struct{})
	delivered := make(chan stageBatch, 2)
	var once sync.Once
	h.start(func(b stageBatch) { once.Do(func() { close(entered); <-release }); delivered <- b })
	h.batches <- h.collect(time.Time{})
	<-entered
	h.batches <- h.collect(time.Time{})
	time.Sleep(120 * time.Millisecond)
	close(release)
	<-delivered
	select {
	case b := <-delivered:
		if b.ExportAgeMS < 100 {
			t.Fatal("queued export age lost")
		}
	case <-time.After(time.Second):
		t.Fatal("export blocked")
	}
}

func TestStageEvidenceSlowEventContainsActualInterval(t *testing.T) {
	h := testStageHub(t)
	e := h.attach(nil)
	defer e.close()
	op := e.beginRead(stagePipeWrite, cmdPSH, 4)
	time.Sleep(120 * time.Millisecond)
	e.finishRead(op, nil)
	batch := h.collect(time.Now().Add(-time.Hour))
	if len(batch.SlowEvents) != 1 {
		t.Fatal("slow event missing")
	}
	event := batch.SlowEvents[0]
	start, err := time.Parse(time.RFC3339Nano, event.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC3339Nano, event.CompletedAt)
	if err != nil {
		t.Fatal(err)
	}
	delta := float64(end.Sub(start))/float64(time.Millisecond) - event.DurationMS
	if delta < -1 || delta > 1 || end.Before(start) || start.Before(op.started.Add(-time.Millisecond)) {
		t.Fatal("slow interval is not tied to operation")
	}
}
