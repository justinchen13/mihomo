package session

import (
	"errors"
	"testing"
	"time"
)

// This negative control runs against the deployed source too: a full bounded
// queue must not allocate strings for an event that cannot be published.
func TestStageSlowFullQueueDoesNotFormatTimestamp(t *testing.T) {
	h := testStageHub(t)
	e := h.attach(nil)
	defer e.close()
	s, ok := e.lock()
	if !ok {
		t.Fatal("slot")
	}
	defer s.mu.Unlock()
	start := time.Date(2026, 10, 23, 1, 2, 3, 456789123, time.FixedZone("source", 10800))
	end := start.Add(250 * time.Millisecond)
	for i := 0; i < evidenceSlowClassCapacity[stageTLSWrite]; i++ {
		e.slowEvent(s, stageTLSWrite, "data", 32775, start, end, end.Sub(start), nil)
	}
	allocs := testing.AllocsPerRun(100, func() {
		e.slowEvent(s, stageTLSWrite, "data", 32775, start, end, end.Sub(start), nil)
	})
	if allocs != 0 {
		t.Fatalf("full queue formatted discarded timestamps: %g allocations/event", allocs)
	}
}

func TestStageSlowTimestampsPreserveOperationTime(t *testing.T) {
	h := testStageHub(t)
	e := h.attach(nil)
	defer e.close()
	start := time.Date(2026, 10, 23, 1, 2, 3, 456789123, time.FixedZone("source", 10800))
	end := start.Add(250 * time.Millisecond)
	s, ok := e.lock()
	if !ok {
		t.Fatal("slot")
	}
	e.slowEvent(s, stageTLSWrite, "data", 32775, start, end, end.Sub(start), errors.New("fixture"))
	s.mu.Unlock()
	var batch stageBatch
	h.collectSlow(&batch)
	if len(batch.SlowEvents) != 1 {
		t.Fatalf("events: %d", len(batch.SlowEvents))
	}
	event := batch.SlowEvents[0]
	if event.StartedAt != start.UTC().Format(time.RFC3339Nano) || event.CompletedAt != end.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("collection substituted source times: %+v", event)
	}
	if event.DurationMS != 250 || !event.Failed || event.Frame != "data" || event.Bytes != 32775 || event.Stage != "tls_write" || event.Session != s.session {
		t.Fatalf("event identity/value changed: %+v", event)
	}
	q := batch.SlowQueueStats[stageTLSWrite]
	if q.Attempted != 1 || q.Admitted != 1 || q.Dequeued != 1 || q.Dropped != 0 || batch.LostSlow != 0 {
		t.Fatalf("accounting: %+v", q)
	}
}
