package route

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/transport/anytls/session"
)

func TestAnyTLSStageHistoryRouteUnixOnly(t *testing.T) {
	for _, debug := range []bool{false, true} {
		public := router(debug, "", "", Cors{})
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			w := httptest.NewRecorder()
			public.ServeHTTP(w, httptest.NewRequest(method, "/diagnostics/anytls-stage/history?epoch=0123456789abcdef&after=1", nil))
			if w.Code != http.StatusNotFound {
				t.Fatal("history exposed to public controller")
			}
		}
		private := unixRouter(debug, "", Cors{})
		w := httptest.NewRecorder()
		private.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/diagnostics/anytls-stage/history?epoch=0123456789abcdef&after=1", nil))
		var out session.StageEvidenceSnapshot
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Availability != "inactive" {
			t.Fatal("Unix inactive contract")
		}
		w = httptest.NewRecorder()
		private.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/diagnostics/anytls-stage/history", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatal("history is not read-only")
		}
	}
}

func TestAnyTLSStageHistoryCursorValidationAndHeaderContract(t *testing.T) {
	calls := 0
	handler := stageEvidenceHistoryHandler(func(epoch string, after uint64) session.StageEvidenceSnapshot {
		calls++
		if epoch != "0123456789abcdef" || after != 1 {
			t.Fatal("cursor changed")
		}
		sequence, age := uint64(2), float64(11000)
		return session.StageEvidenceSnapshot{Schema: 1, Kind: "anytls_stage_snapshot", Availability: "ready", EvidenceEpoch: &epoch, Sequence: &sequence, AgeMS: &age,
			Snapshot: json.RawMessage(`{}`), History: &session.StageEvidenceHistory{OldestSequence: 1, LatestSequence: 3, LatestAgeMS: 1000, Gap: "none"}}
	})
	for _, query := range []string{"", "epoch=0123456789abcdef", "epoch=bad&after=1", "epoch=0123456789abcdef&after=-1", "epoch=0123456789abcdef&after=01", "epoch=0123456789abcdef&after=18446744073709551616", "epoch=0123456789abcdef&after=1&after=2", "epoch=0123456789abcdef&after=1&unknown=x", "epoch=0123456789abcdef&after=1&bad=%zz", strings.Repeat("x", 129)} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, "/diagnostics/anytls-stage/history?"+query, nil))
		if w.Code != http.StatusBadRequest || w.Body.Len() > 256 || calls != 0 {
			t.Fatal("unbounded/invalid cursor accepted")
		}
	}
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodGet, "/diagnostics/anytls-stage/history?epoch=0123456789abcdef&after=1", nil))
	if w.Code != 200 || calls != 1 || w.Header().Get("X-PCS-Stage-Oldest") != "1" || w.Header().Get("X-PCS-Stage-Latest") != "3" || w.Header().Get("X-PCS-Stage-Latest-Age-Ms") != "1000.000" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("bounded metadata headers")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &fields) != nil || len(fields) != 8 || fields["history"] != nil {
		t.Fatal("legacy body shape changed")
	}
}
