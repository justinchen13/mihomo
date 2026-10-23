package session

import (
	"syscall"
	"testing"
	"time"
)

func stageHistoryCPU() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		panic(err)
	}
	return usage.Utime.Sec*1e9 + usage.Utime.Usec*1000 + usage.Stime.Sec*1e9 + usage.Stime.Usec*1000
}

func benchmarkStageHistoryHub(b *testing.B) (*stageHub, stageBatch) {
	h := newStageHub()
	if h == nil {
		b.Fatal("hub")
	}
	b.Cleanup(h.close)
	for i := 0; i < 32; i++ {
		e := h.attach(nil)
		b.Cleanup(e.close)
		op := e.beginRead(stageReadBody, cmdPSH, 32768)
		op.started = time.Now().Add(-150 * time.Millisecond)
		e.finishRead(op, nil)
	}
	batch := h.collect(time.Now())
	h.publish(batch)
	return h, batch
}

func BenchmarkStageHistoryPublish32(b *testing.B) {
	h, batch := benchmarkStageHistoryHub(b)
	b.ReportAllocs()
	b.ResetTimer()
	cpu := stageHistoryCPU()
	for i := 0; i < b.N; i++ {
		batch.Sequence = uint64(i + 1)
		h.publish(batch)
	}
	b.StopTimer()
	b.ReportMetric(float64(stageHistoryCPU()-cpu)/float64(b.N), "cpu-ns/op")
}

func BenchmarkStageHistoryLegacyRead(b *testing.B) {
	h, _ := benchmarkStageHistoryHub(b)
	b.ReportAllocs()
	b.ResetTimer()
	cpu := stageHistoryCPU()
	for i := 0; i < b.N; i++ {
		if h.readPublication().Sequence == nil {
			b.Fatal("missing")
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(stageHistoryCPU()-cpu)/float64(b.N), "cpu-ns/op")
}
