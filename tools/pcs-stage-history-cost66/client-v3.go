// Test-only full TLS/AnyTLS fixture v3: 66s workload; distinct client source address.
// This file is outside the proxy source tree; the original fixture is retained.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	M "github.com/metacubex/sing/common/metadata"
)

const scheme = "stop=3\n0=30-30\n1=300-300\n2=600-600"
const name = "anytls-runtime.test"
const bulkBytes = 128 * 1024 * 1024
const uploadBytes = 16 * 1024 * 1024
const smallCount = 528
const smallBytes = 4096
const active = 66 * time.Second
const workloadDeadline = active + 27*time.Second

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func stamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func save(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	tmp := path + ".tmp"
	if e = os.WriteFile(tmp, append(b, '\n'), 0600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func waitFile(path string, deadline time.Time) error {
	for time.Now().Before(deadline) {
		if _, e := os.Stat(path); e == nil {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return errors.New("fixture file deadline")
}
func fill(b []byte, offset uint64, seed uint32) {
	for i := range b {
		b[i] = byte((offset+uint64(i))*31 + uint64(seed)*17)
	}
}
func digest(n uint64, seed uint32) string {
	h := sha256.New()
	b := make([]byte, 32768)
	for o := uint64(0); o < n; {
		k := min64(uint64(len(b)), n-o)
		fill(b[:k], o, seed)
		h.Write(b[:k])
		o += k
	}
	return hex.EncodeToString(h.Sum(nil))
}
func split(n, total, index int) int {
	q := n / total
	if index < n%total {
		q++
	}
	return q
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func request(w io.Writer, op byte, n uint64, d time.Duration, seed uint32, phase ...time.Duration) error {
	b := make([]byte, 21)
	b[0] = op
	binary.BigEndian.PutUint64(b[1:9], n)
	binary.BigEndian.PutUint32(b[9:13], uint32(d/time.Millisecond))
	binary.BigEndian.PutUint32(b[13:17], seed)
	if len(phase) > 0 {
		binary.BigEndian.PutUint32(b[17:21], uint32(phase[0]/time.Microsecond))
	}
	return writeAll(w, b)
}
func pacedWrite(w io.Writer, n uint64, d time.Duration, seed uint32, phase ...time.Duration) error {
	start := time.Now()
	if len(phase) > 0 {
		start = start.Add(phase[0])
	}
	b := make([]byte, 32768)
	for o := uint64(0); o < n; {
		if d > 0 {
			deadline := start.Add(time.Duration(float64(d) * float64(o) / float64(n)))
			if delay := time.Until(deadline); delay > 0 {
				time.Sleep(delay)
			}
		}
		k := min64(uint64(len(b)), n-o)
		fill(b[:k], o, seed)
		if e := writeAll(w, b[:k]); e != nil {
			return e
		}
		o += k
	}
	return nil
}
func receive(r io.Reader, n uint64, counter *atomic.Uint64) (string, error) {
	h := sha256.New()
	b := make([]byte, 32768)
	for o := uint64(0); o < n; {
		k := min64(uint64(len(b)), n-o)
		nr, e := io.ReadFull(r, b[:k])
		if nr > 0 {
			h.Write(b[:nr])
			o += uint64(nr)
			if counter != nil {
				counter.Add(uint64(nr))
			}
		}
		if e != nil {
			return "", e
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func origin(dir string) error {
	l, e := net.Listen("tcp4", "127.0.0.1:19081")
	if e != nil {
		return e
	}
	defer l.Close()
	if e = save(filepath.Join(dir, "origin-ready.json"), map[string]any{"ready": true, "pid": os.Getpid(), "utc": stamp()}); e != nil {
		return e
	}
	var wg sync.WaitGroup
	var completed atomic.Uint64
	var errs atomic.Uint64
	go func() { _ = waitFile(filepath.Join(dir, "stop"), time.Now().Add(240*time.Second)); l.Close() }()
	for {
		c, e := l.Accept()
		if e != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(180 * time.Second))
			header := make([]byte, 21)
			for {
				_, e := io.ReadFull(c, header)
				if e == io.EOF {
					return
				}
				if e != nil {
					errs.Add(1)
					return
				}
				op := header[0]
				n := binary.BigEndian.Uint64(header[1:9])
				duration := time.Duration(binary.BigEndian.Uint32(header[9:13])) * time.Millisecond
				seed := binary.BigEndian.Uint32(header[13:17])
				phase := time.Duration(binary.BigEndian.Uint32(header[17:21])) * time.Microsecond
				if n > bulkBytes || duration > active+7*time.Second || phase > active {
					errs.Add(1)
					return
				}
				switch op {
				case 1:
					e = pacedWrite(c, n, duration, seed, phase)
				case 2:
					var sum string
					sum, e = receive(c, n, nil)
					if e == nil {
						raw, _ := hex.DecodeString(sum)
						e = writeAll(c, raw)
					}
				default:
					e = errors.New("unsupported fixture op")
				}
				if e != nil {
					errs.Add(1)
					return
				}
				completed.Add(1)
			}
		}()
	}
	// Closing the proxy/client before stop is the normal runner order.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
	return save(filepath.Join(dir, "origin-result.json"), map[string]any{"completed_requests": completed.Load(), "io_errors_including_cleanup": errs.Load(), "utc": stamp()})
}

type Outer struct {
	session              *session.Session
	streams              [3]*session.Stream
	raw                  *tls.Conn
	bulkN, uploadN       int
	bulkHash, uploadHash string
	pad                  *atomic.Pointer[padding.PaddingFactory]
}
type Small struct {
	Index           int     `json:"index"`
	Outer           int     `json:"outer_ordinal"`
	ScheduledUTC    string  `json:"scheduled_utc"`
	StartedUTC      string  `json:"started_utc"`
	CompletedUTC    string  `json:"completed_utc"`
	ScheduleDelayMS float64 `json:"schedule_delay_ms"`
	ClientMS        float64 `json:"client_send_to_verified_ms"`
	TotalMS         float64 `json:"scheduled_to_verified_ms"`
	Bytes           int     `json:"received_body_bytes"`
	SHA256          string  `json:"sha256"`
	OK              bool    `json:"ok"`
	Error           string  `json:"error_class,omitempty"`
}

func makeOuter(cafile, password string, index, n int) (o *Outer, err error) {
	pem, e := os.ReadFile(cafile)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("fixture CA")
	}
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}, "tcp4", "127.0.0.1:7443", &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if e != nil {
		return nil, e
	}
	good := false
	defer func() {
		if !good {
			conn.Close()
		}
	}()
	// DIRECT's safety detector keys local IP+port. Keep the synthetic client
	// source distinct from proxy-to-origin sockets without disabling protection.
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || local == nil || !local.IP.Equal(net.IPv4(127, 0, 0, 2)) || local.Port <= 0 {
		return nil, errors.New("fixture outer source bind mismatch")
	}
	if len(conn.ConnectionState().VerifiedChains) == 0 {
		return nil, errors.New("unverified TLS")
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	sum := sha256.Sum256([]byte(password))
	auth := append(sum[:], 0, 64)
	auth = append(auth, make([]byte, 64)...)
	if e = writeAll(conn, auth); e != nil {
		return nil, e
	}
	pad := new(atomic.Pointer[padding.PaddingFactory])
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, pad) {
		return nil, errors.New("initial padding")
	}
	s := session.NewClientSession(conn, pad)
	s.Run()
	o = &Outer{session: s, raw: conn, pad: pad, bulkN: split(bulkBytes, n, index), uploadN: split(uploadBytes, n, index)}
	for j := range o.streams {
		st, e := s.OpenStream()
		if e != nil {
			return nil, e
		}
		o.streams[j] = st
		if e = M.SocksaddrSerializer.WriteAddrPort(st, M.ParseSocksaddr("127.0.0.1:19081")); e != nil {
			return nil, e
		}
		if e = request(st, 1, 1, 0, uint32(index*3+j)); e != nil {
			return nil, e
		}
		got, e := receive(st, 1, nil)
		if e != nil || got != digest(1, uint32(index*3+j)) {
			return nil, errors.New("prime integrity")
		}
	}
	if string(pad.Load().RawScheme) != scheme {
		return nil, errors.New("padding not negotiated")
	}
	_ = conn.SetDeadline(time.Time{})
	o.bulkHash = digest(uint64(o.bulkN), uint32(index))
	o.uploadHash = digest(uint64(o.uploadN), uint32(1000+index))
	good = true
	return o, nil
}
func client(dir, cafile, password string, n int) error {
	if n != 1 && n != 32 && n != 66 {
		return errors.New("unsupported outer count")
	}
	started := stamp()
	smallExpected := make([]string, smallCount)
	for i := range smallExpected {
		smallExpected[i] = digest(smallBytes, uint32(2000+i))
	}
	outers := make([]*Outer, 0, n)
	defer func() {
		for _, o := range outers {
			o.session.Close()
		}
	}()
	for i := 0; i < n; i++ {
		o, e := makeOuter(cafile, password, i, n)
		if e != nil {
			return e
		}
		outers = append(outers, o)
	}
	if e := save(filepath.Join(dir, "client-ready.json"), map[string]any{"ready": true, "outer_sessions": n, "streams": 3 * n, "tls_verified": n, "padding_verified": n, "outer_source_bind_verified": n, "pid": os.Getpid(), "setup_started_utc": started, "ready_utc": stamp()}); e != nil {
		return e
	}
	if e := waitFile(filepath.Join(dir, "go"), time.Now().Add(50*time.Second)); e != nil {
		return e
	}
	began := time.Now()
	var down atomic.Uint64
	var upload atomic.Uint64
	go func() {
		time.Sleep(time.Second)
		_ = save(filepath.Join(dir, "first-second-client.json"), map[string]any{"utc": stamp(), "elapsed_seconds": time.Since(began).Seconds(), "downstream_body_bytes": down.Load(), "note": "actual workload progress; not delivery capacity"})
	}()
	var errsMu sync.Mutex
	errs := []string{}
	failure := func(s string) { errsMu.Lock(); errs = append(errs, s); errsMu.Unlock() }
	var wg sync.WaitGroup
	bulkEnd := make([]time.Time, n)
	var bulkStart time.Time
	var bulkMu sync.Mutex
	for i, o := range outers {
		for _, st := range o.streams {
			_ = st.SetDeadline(began.Add(workloadDeadline))
		}
		wg.Add(2)
		go func(i int, o *Outer) {
			defer wg.Done()
			start := time.Now()
			bulkMu.Lock()
			if bulkStart.IsZero() || start.Before(bulkStart) {
				bulkStart = start
			}
			bulkMu.Unlock()
			if e := request(o.streams[0], 1, uint64(o.bulkN), active, uint32(i), time.Duration(float64(active)*float64(min64(32768, uint64(o.bulkN)))/float64(o.bulkN)*float64(i)/float64(n))); e != nil {
				failure("bulk_request")
				return
			}
			got, e := receive(o.streams[0], uint64(o.bulkN), &down)
			if e != nil || got != o.bulkHash {
				failure("bulk_integrity")
				return
			}
			bulkEnd[i] = time.Now()
		}(i, o)
		go func(i int, o *Outer) {
			defer wg.Done()
			if e := request(o.streams[2], 2, uint64(o.uploadN), 0, uint32(1000+i)); e != nil {
				failure("upload_request")
				return
			}
			if e := pacedWrite(o.streams[2], uint64(o.uploadN), active, uint32(1000+i), time.Duration(float64(active)*float64(min64(32768, uint64(o.uploadN)))/float64(o.uploadN)*float64(i)/float64(n))); e != nil {
				failure("upload_write")
				return
			}
			upload.Add(uint64(o.uploadN))
			b := make([]byte, 32)
			if _, e := io.ReadFull(o.streams[2], b); e != nil || hex.EncodeToString(b) != o.uploadHash {
				failure("upload_digest")
				return
			}
			down.Add(32)
		}(i, o)
	}
	results := make([]Small, smallCount)
	sem := make(chan struct{}, 8)
	locks := make([]sync.Mutex, n)
	for index := 0; index < smallCount; index++ {
		index := index
		scheduled := began.Add(time.Duration(float64(active) * float64(index) / smallCount))
		if d := time.Until(scheduled); d > 0 {
			time.Sleep(d)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			outer := index % n
			r := Small{Index: index, Outer: outer, ScheduledUTC: scheduled.UTC().Format(time.RFC3339Nano), Bytes: smallBytes}
			locks[outer].Lock()
			defer locks[outer].Unlock()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			r.StartedUTC = start.UTC().Format(time.RFC3339Nano)
			r.ScheduleDelayMS = float64(start.Sub(scheduled)) / float64(time.Millisecond)
			e := request(outers[outer].streams[1], 1, smallBytes, 0, uint32(2000+index))
			var got string
			if e == nil {
				got, e = receive(outers[outer].streams[1], smallBytes, &down)
			}
			r.OK = e == nil && got == smallExpected[index]
			end := time.Now()
			r.CompletedUTC = end.UTC().Format(time.RFC3339Nano)
			r.ClientMS = float64(end.Sub(start)) / float64(time.Millisecond)
			r.TotalMS = float64(end.Sub(scheduled)) / float64(time.Millisecond)
			r.SHA256 = got
			if !r.OK {
				r.Error = "small_integrity"
				failure(r.Error)
			}
			results[index] = r
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Until(began.Add(workloadDeadline))):
		failure("workload_timeout")
		for _, o := range outers {
			o.session.Close()
		}
		<-done
	}
	ended := time.Now()
	values := make([]float64, 0, smallCount)
	for _, r := range results {
		if r.OK {
			values = append(values, r.TotalMS)
		}
	}
	sort.Float64s(values)
	p95 := 0.0
	if len(values) == smallCount {
		p95 = values[(smallCount*95+99)/100-1]
	}
	last := bulkStart
	for _, end := range bulkEnd {
		if end.After(last) {
			last = end
		}
	}
	bulkSeconds := last.Sub(bulkStart).Seconds()
	live := 0
	for _, o := range outers {
		if !o.session.IsClosed() {
			live++
		}
	}
	expected := uint64(bulkBytes + smallCount*smallBytes + n*32)
	result := map[string]any{"ok": len(errs) == 0 && down.Load() == expected && upload.Load() == uploadBytes && live == n, "errors": errs, "started_utc": began.UTC().Format(time.RFC3339Nano), "completed_utc": ended.UTC().Format(time.RFC3339Nano), "workload_contract": "cost66-payload-v1", "active_seconds": int(active / time.Second), "outer_sessions": n, "live_sessions_at_finish": live, "streams": n * 3, "tls_verified": n, "padding_verified": n, "outer_source_bind_verified": n, "received_body_bytes": down.Load(), "expected_received_body_bytes": expected, "upload_verified_bytes": upload.Load(), "bulk_body_bytes": bulkBytes, "bulk_wall_seconds": bulkSeconds, "bulk_decimal_MB_per_second": float64(bulkBytes) / 1e6 / bulkSeconds, "small_count": smallCount, "small_all_verified": len(values) == smallCount, "small_p95_scheduled_to_verified_ms": p95, "small": results, "first_second_workload_note": "origin starts bulk immediately; runner independently checks server traffic or socket counters at first second"}
	if e := save(filepath.Join(dir, "client-result.json"), result); e != nil {
		return e
	}
	// Hold every outer while runner captures the fixed one-second settle interval.
	if e := waitFile(filepath.Join(dir, "finish"), time.Now().Add(8*time.Second)); e != nil {
		return e
	}
	if len(errs) > 0 {
		return errors.New("fixture integrity failure")
	}
	return nil
}
func main() {
	mode := flag.String("mode", "", "origin or client")
	dir := flag.String("dir", "", "private output")
	cafile := flag.String("ca", "", "fixture certificate")
	users := flag.String("users", "", "private fixture users")
	n := flag.Int("sessions", 1, "outer sessions")
	flag.Parse()
	os.MkdirAll(*dir, 0700)
	var err error
	switch *mode {
	case "origin":
		err = origin(*dir)
	case "client":
		b, e := os.ReadFile(*users)
		if e != nil {
			err = e
			break
		}
		var u map[string]string
		if e = json.Unmarshal(b, &u); e != nil {
			err = e
			break
		}
		err = client(*dir, *cafile, u["fixture-one"], *n)
	default:
		err = errors.New("unsupported mode")
	}
	if err != nil {
		_ = save(filepath.Join(*dir, *mode+"-failure.json"), map[string]any{"ok": false, "phase": *mode, "error_class": "fixture_failed", "utc": stamp()})
		fmt.Fprintln(os.Stderr, "fixture failed")
		os.Exit(1)
	}
}
