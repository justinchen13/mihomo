package session

import (
	"encoding/json"
	"testing"
	"time"
)

// On the deployed baseline this intentionally calls the actual latest-only
// reader. The same deterministic schedule must retain publication2 after the
// producer advances through3 between pulls; it cannot be inferred from3.
func TestStageHistoryCursorRecoversIntermediatePublication(t *testing.T) {
	h := testStageHub(t)
	publish := func(sequence uint64, marker int) {
		batch := h.collect(time.Now())
		batch.Sequence = sequence
		batch.SlowEvents = []stageSlowEvent{{Stage: "tls_write", Frame: "data", Bytes: marker, DurationMS: 150}}
		h.publish(batch)
	}
	readAfter := func(after uint64) StageEvidenceSnapshot {
		if cursor, ok := any(h).(interface {
			readPublicationAfter(string, uint64) StageEvidenceSnapshot
		}); ok {
			return cursor.readPublicationAfter(h.nonce, after)
		}
		return h.readPublication()
	}
	publish(1, 101)
	first := h.readPublication()
	if first.Sequence == nil || *first.Sequence != 1 {
		t.Fatal("initial publication")
	}
	publish(2, 202)
	publish(3, 303)
	next := readAfter(1)
	if next.Sequence == nil || *next.Sequence != 2 {
		actual := uint64(0)
		if next.Sequence != nil {
			actual = *next.Sequence
		}
		t.Fatalf("intermediate publication lost: cursor1 returned %d; latest-only cannot recover2", actual)
	}
	var batch stageBatch
	if err := json.Unmarshal(next.Snapshot, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.SlowEvents) != 1 || batch.SlowEvents[0].Bytes != 202 {
		t.Fatal("publication event identity lost")
	}
	last := readAfter(2)
	if last.Sequence == nil || *last.Sequence != 3 {
		t.Fatal("did not advance to3")
	}
}
