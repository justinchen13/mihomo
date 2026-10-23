package session

import (
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func lazyStageCPU() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		panic(err)
	}
	return usage.Utime.Sec*1e9 + usage.Utime.Usec*1000 + usage.Stime.Sec*1e9 + usage.Stime.Usec*1000
}

func BenchmarkStageSlowFullQueueRecord(b *testing.B) {
	h := newStageHub()
	if h == nil {
		b.Fatal("hub")
	}
	defer h.close()
	e := h.attach(nil)
	defer e.close()
	s, ok := e.lock()
	if !ok {
		b.Fatal("slot")
	}
	defer s.mu.Unlock()
	start := time.Now().Add(-250 * time.Millisecond)
	end := start.Add(250 * time.Millisecond)
	for i := 0; i < evidenceSlowClassCapacity[stageTLSWrite]; i++ {
		e.slowEvent(s, stageTLSWrite, "data", 32775, start, end, end.Sub(start), nil)
	}
	b.ReportAllocs()
	b.ResetTimer()
	cpuStart := lazyStageCPU()
	defer func() {
		b.StopTimer()
		b.ReportMetric(float64(lazyStageCPU()-cpuStart)/float64(b.N), "cpu-ns/op")
		b.ReportMetric(float64(unsafe.Sizeof(stageSlowEvent{})), "event-bytes")
	}()
	for i := 0; i < b.N; i++ {
		e.slowEvent(s, stageTLSWrite, "data", 32775, start, end, end.Sub(start), nil)
	}
}

func BenchmarkStageSlowRecordCollectCycle(b *testing.B) {
	h := newStageHub()
	if h == nil {
		b.Fatal("hub")
	}
	defer h.close()
	e := h.attach(nil)
	defer e.close()
	s, ok := e.lock()
	if !ok {
		b.Fatal("slot")
	}
	defer s.mu.Unlock()
	start := time.Now().Add(-250 * time.Millisecond)
	end := start.Add(250 * time.Millisecond)
	b.ReportAllocs()
	b.ResetTimer()
	cpuStart := lazyStageCPU()
	defer func() {
		b.StopTimer()
		b.ReportMetric(float64(lazyStageCPU()-cpuStart)/float64(b.N), "cpu-ns/op")
		b.ReportMetric(float64(unsafe.Sizeof(stageSlowEvent{})), "event-bytes")
	}()
	for i := 0; i < b.N; i++ {
		e.slowEvent(s, stageTLSWrite, "data", 32775, start, end, end.Sub(start), nil)
		var batch stageBatch
		h.collectSlow(&batch)
	}
}
