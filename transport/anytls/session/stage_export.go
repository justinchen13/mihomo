package session

import (
	"encoding/json"
	"time"
)

// StageEvidenceMaxResponseBytes bounds the entire JSON response body. The
// inner publication leaves room for its fixed-size envelope. No evidence is
// sent to the shared logger or its subscribers.
const StageEvidenceMaxResponseBytes = 64 * 1024
const stageEvidenceBodyLimit = StageEvidenceMaxResponseBytes - 1024

type stagePublication struct {
	raw      json.RawMessage // immutable after atomic publication
	captured time.Time
	sequence uint64
}

type StageEvidenceSnapshot struct {
	Schema        int             `json:"schema"`
	Kind          string          `json:"kind"`
	Availability  string          `json:"availability"`
	EvidenceEpoch *string         `json:"evidence_epoch"`
	Sequence      *uint64         `json:"sequence"`
	AgeMS         *float64        `json:"age_ms"`
	FailedExports uint64          `json:"failed_exports_total"`
	Snapshot      json.RawMessage `json:"snapshot"`
}

// ReadServerStageEvidence reads only a cached publication. It never collects,
// waits on a session/registry mutex, or creates an observer. Inactive includes
// both a disabled listener and no authenticated opt-in session yet; it is not
// evidence of zero active proxy sessions. Callers may mutate their returned
// bytes without modifying the publication seen by another request.
func ReadServerStageEvidence() StageEvidenceSnapshot {
	return serverStageHub.Load().readPublication()
}

func (h *stageHub) readPublication() StageEvidenceSnapshot {
	out := StageEvidenceSnapshot{Schema: 1, Kind: "anytls_stage_snapshot", Availability: "inactive"}
	if h == nil {
		return out
	}
	epoch := h.nonce
	out.EvidenceEpoch = &epoch
	out.FailedExports = h.failedExports.Load()
	out.Availability = "awaiting_sample"
	p := h.latest.Load()
	if p == nil {
		return out
	}
	sequence := p.sequence
	age := float64(time.Since(p.captured)) / float64(time.Millisecond)
	out.Availability = "ready"
	out.Sequence, out.AgeMS = &sequence, &age
	out.Snapshot = append(json.RawMessage(nil), p.raw...)
	return out
}

// Called by the one bounded exporter, outside every observer/session mutex.
// Overwrite retains exactly one immutable body; there is no history queue here.
func (h *stageHub) publish(b stageBatch) {
	raw, err := json.Marshal(b)
	if len(raw) > stageEvidenceBodyLimit {
		b.PayloadLimited = true
		b.OmittedSessions = len(b.Sessions)
		b.OmittedSlow = len(b.SlowEvents)
		for _, event := range b.SlowEvents {
			for i, name := range evidenceStageNames {
				if event.Stage == name {
					b.OmittedSlowByClass[i]++
					break
				}
			}
		}
		b.Sessions, b.SlowEvents = nil, nil
		raw, err = json.Marshal(b)
	}
	if err != nil || len(raw) > stageEvidenceBodyLimit {
		h.failedExports.Add(1)
		return
	}
	h.latest.Store(&stagePublication{raw: raw, captured: b.Captured, sequence: b.Sequence})
}
