package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This projection has exactly the original schema-1 wire fields. RawMessage
// preserves the Go encoder's canonical numbers; map ordering changes no sizes.
func stageSchemaOneBody(t *testing.T, batch stageBatch) []byte {
	t.Helper()
	batch.Schema = 1
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "slow_event_policy")
	delete(fields, "slow_queue_counters")
	delete(fields, "omitted_slow_events_by_class")
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStageSlowClassPublicationBudget(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "experiments", "fixtures", "anytls-stage-full-session.json")
	fixture, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, withCompletions := range []bool{false, true} {
		shape := "observed64Snapshots"
		if withCompletions {
			shape = "observed64SnapshotsPlusLegal32Completions"
		}
		for _, widestCounters := range []bool{false, true} {
			width := "smallCounters"
			if widestCounters {
				width = "uint64WidthBound"
			}
			t.Run(shape+"/"+width, func(t *testing.T) {
				var batch stageBatch
				if err := json.Unmarshal(fixture, &batch); err != nil {
					t.Fatal(err)
				}
				active, evicted := 0, 0
				var activeSessions []string
				for _, snapshot := range batch.Sessions {
					if snapshot.Status == "active" && snapshot.Known {
						active++
						activeSessions = append(activeSessions, snapshot.Session)
					}
					if snapshot.Status == "evicted" && !snapshot.Known {
						evicted++
					}
				}
				// collect may append its bounded terminal ring to the live slots.
				// These are 32 live + 32 eviction records, not 64 tracked sessions.
				if len(batch.Sessions) != 64 || active != 32 || evicted != 32 || batch.Live != 66 || batch.Tracked != 32 || batch.Untracked != 34 || len(batch.SlowEvents) != 0 {
					t.Fatal("full real-TLS fixture shape changed")
				}
				batch.Schema = 2
				batch.SlowEventPolicy = evidenceSlowPolicy
				batch.Captured = time.Now()
				completed, err := time.Parse(time.RFC3339Nano, batch.CaptureEnded)
				if err != nil {
					t.Fatal(err)
				}
				for stage, capacity := range evidenceSlowClassCapacity {
					batch.SlowQueueStats[stage].Capacity = capacity
					if withCompletions {
						// A declared synthetic composite: the retained real session
						// shape plus one legal full six-class completion queue.
						// This is not claimed to be a captured production event.
						for i := 0; i < capacity; i++ {
							batch.SlowEvents = append(batch.SlowEvents, stageSlowEvent{
								Session:     activeSessions[(stage*8+i)%32],
								StartedAt:   completed.Add(-time.Second).Format(time.RFC3339Nano),
								CompletedAt: completed.Format(time.RFC3339Nano),
								Stage:       evidenceStageNames[stage], Frame: "data", Bytes: 32775,
								DurationMS: 1000, completed: completed,
							})
						}
						batch.SlowQueueStats[stage].Attempted = uint64(capacity)
						batch.SlowQueueStats[stage].Admitted = uint64(capacity)
						batch.SlowQueueStats[stage].Dequeued = uint64(capacity)
					}
					if widestCounters {
						// Serialization width bound only; not an assertion that
						// these four counters are an atomic realizable state.
						batch.SlowQueueStats[stage].Attempted = ^uint64(0)
						batch.SlowQueueStats[stage].Admitted = ^uint64(0)
						batch.SlowQueueStats[stage].Dropped = ^uint64(0)
						batch.SlowQueueStats[stage].Dequeued = ^uint64(0)
					}
				}
				legacy := stageSchemaOneBody(t, batch)
				candidate, err := json.Marshal(batch)
				if err != nil {
					t.Fatal(err)
				}
				baselineFits := len(legacy) <= stageEvidenceBodyLimit
				candidateFits := len(candidate) <= stageEvidenceBodyLimit
				if !withCompletions && !baselineFits {
					t.Fatal("retained observed fixture unexpectedly exceeds the original inner limit")
				}
				h := testStageHub(t)
				h.publish(batch)
				publication := h.readPublication()
				body, err := json.Marshal(publication)
				if err != nil {
					t.Fatal(err)
				}
				var exported stageBatch
				if err := json.Unmarshal(publication.Snapshot, &exported); err != nil {
					t.Fatal(err)
				}
				t.Logf("S1_BODY_BYTES legacy=%d candidate=%d published_inner=%d response=%d old_fits=%t candidate_fits=%t payload_limited=%t omitted_sessions=%d omitted_slow=%d class_omissions=%v", len(legacy), len(candidate), len(publication.Snapshot), len(body), baselineFits, candidateFits, exported.PayloadLimited, exported.OmittedSessions, exported.OmittedSlow, exported.OmittedSlowByClass)
				if baselineFits && !candidateFits {
					t.Fatal("schema2 causes whole-publication detail loss where schema1 fits; release cost remains HOLD")
				}
				if len(body) > StageEvidenceMaxResponseBytes || len(publication.Snapshot) > stageEvidenceBodyLimit || publication.FailedExports != 0 {
					t.Fatal("original byte limit or bounded publication failed")
				}
				if candidateFits {
					if exported.PayloadLimited || len(exported.Sessions) != 64 || len(exported.SlowEvents) != len(batch.SlowEvents) || exported.OmittedSessions != 0 || exported.OmittedSlow != 0 {
						t.Fatal("unexpected detail omission below the original byte limit")
					}
				} else {
					// The baseline was also over budget. Preserve this original
					// coverage limitation instead of blaming only the new fields.
					if !exported.PayloadLimited || exported.Sessions != nil || exported.SlowEvents != nil || exported.OmittedSessions != 64 || exported.OmittedSlow != len(batch.SlowEvents) {
						t.Fatal("pre-existing overflow lacks explicit omissions")
					}
					for stage, capacity := range evidenceSlowClassCapacity {
						if exported.OmittedSlowByClass[stage] != capacity {
							t.Fatal("overflow lost the fixed per-class omissions")
						}
					}
				}
			})
		}
	}
}
