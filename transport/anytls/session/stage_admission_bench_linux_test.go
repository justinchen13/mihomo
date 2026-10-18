package session

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Pure registry churn only, identical fixture compilable on 68b13. This does
// not simulate connections or estimate proxy/network speed. Every iteration
// keeps exactly 32 live slots, replacing and closing the evicted handle.
func BenchmarkStageAdmissionChurn(b *testing.B) {
	for _, shape := range []string{"idle", "one_slow_writer", "all_slow"} {
		b.Run(shape, func(b *testing.B) {
			h := newStageHub()
			if h == nil {
				b.Fatal("random source")
			}
			defer h.close()
			var handles [evidenceSessions]*stageHandle
			old := time.Now().Add(-time.Hour)
			mark := func(index int) {
				h.slots[index].owner = stageWaiter{}
				if shape == "all_slow" || shape == "one_slow_writer" && index == 0 {
					h.slots[index].owner = stageWaiter{used: true, started: old}
				}
			}
			for i := range handles {
				handles[i] = h.attach(nil)
				mark(i)
			}
			cpu := func() float64 {
				var usage unix.Rusage
				if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
					b.Fatal(err)
				}
				return float64(usage.Utime.Sec+usage.Stime.Sec)*1e6 + float64(usage.Utime.Usec+usage.Stime.Usec)
			}
			b.ReportAllocs()
			b.ResetTimer()
			before := cpu()
			for i := 0; i < b.N; i++ {
				if shape == "one_slow_writer" {
					// Keep the decision shape constant in both arms: the rotor
					// starts on the only slow writer, other slots remain idle.
					h.next = 0
				}
				fresh := h.attach(nil)
				stale := handles[fresh.slot]
				handles[fresh.slot] = fresh
				stale.close()
				mark(fresh.slot)
			}
			after := cpu()
			b.StopTimer()
			b.ReportMetric((after-before)/float64(b.N), "cpu-us/op")
			if h.live.Load() != evidenceSessions {
				b.Fatal("benchmark failed to keep the fixed live population")
			}
			for _, handle := range handles {
				handle.close()
			}
		})
	}
}
