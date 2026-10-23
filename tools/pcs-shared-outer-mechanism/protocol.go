// Test-only fixture. No proxy runtime files are changed.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const scheme = "stop=3\n0=30-30\n1=300-300\n2=600-600"
const name = "anytls-runtime.test"
const pairs = 16
const smallCount = 2 * pairs
const requestCount = smallCount + 1
const bulkID = smallCount
const smallBytes = 4096
const bulkBytes = 6 * 1024 * 1024
const deadline = 45 * time.Second
const opReference byte = 1
const opMeasured byte = 3
const maxJSONBytes = 1024 * 1024

// Same 21-byte fixed header width as F2. Duration and phase are reserved zero:
// no application pacing, read sleeps, variable payload or unbounded IDs.
type Header struct {
	Op    byte
	Bytes uint64
	ID    uint32
}

func parseHeader(b []byte) (Header, error) {
	if len(b) != 21 || binary.BigEndian.Uint32(b[9:13]) != 0 || binary.BigEndian.Uint32(b[17:21]) != 0 {
		return Header{}, errors.New("header_shape")
	}
	h := Header{Op: b[0], Bytes: binary.BigEndian.Uint64(b[1:9]), ID: binary.BigEndian.Uint32(b[13:17])}
	if h.Op == opReference && (h.Bytes == 1 || h.Bytes == smallBytes) && h.ID >= 100000 && h.ID < 200000 {
		return h, nil
	}
	if h.Op != opMeasured || h.ID >= requestCount || h.Bytes != payloadBytes(int(h.ID)) {
		return Header{}, errors.New("header_population")
	}
	return h, nil
}

func request(w io.Writer, h Header) error {
	var b [21]byte
	b[0] = h.Op
	binary.BigEndian.PutUint64(b[1:9], h.Bytes)
	binary.BigEndian.PutUint32(b[13:17], h.ID)
	if _, err := parseHeader(b[:]); err != nil {
		return err
	}
	return writeAll(w, b[:])
}

func payloadBytes(id int) uint64 {
	if id == bulkID {
		return bulkBytes
	}
	return smallBytes
}
func seedFor(id int) uint32 { return uint32(2000 + id) }
func outerFor(id, bulkOuter int) int {
	if id == bulkID {
		return bulkOuter
	}
	return id % 2
}
func dueOffset(id int) time.Duration {
	if id == bulkID {
		return 0
	}
	return time.Second + time.Duration(id/2)*500*time.Millisecond
}
func roleFor(id, bulkOuter int) string {
	if id == bulkID {
		return "bulk"
	}
	if outerFor(id, bulkOuter) == bulkOuter {
		return "loaded"
	}
	return "independent"
}
func stamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func save(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b)+1 > maxJSONBytes {
		return errors.New("json_cap")
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func waitFile(path string, until time.Time) error {
	for time.Now().Before(until) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return errors.New("control_file_deadline")
}
func fill(b []byte, offset uint64, seed uint32) {
	for i := range b {
		b[i] = byte((offset+uint64(i))*31 + uint64(seed)*17)
	}
}
func digest(n uint64, seed uint32) string {
	h := sha256.New()
	var b [32768]byte
	for o := uint64(0); o < n; {
		k := uint64(len(b))
		if n-o < k {
			k = n - o
		}
		fill(b[:k], o, seed)
		_, _ = h.Write(b[:k])
		o += k
	}
	return hex.EncodeToString(h.Sum(nil))
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return errors.New("invalid_write_count")
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func receiveSetup(r io.Reader, n uint64) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

func main() {
	mode := flag.String("mode", "", "origin or client; isolated lab only")
	dir := flag.String("dir", "", "existing private output directory")
	ca := flag.String("ca", "", "synthetic CA")
	users := flag.String("users", "", "private synthetic credentials")
	bulkOuter := flag.Int("bulk-outer", -1, "fixed 0 or 1")
	isolated := flag.Bool("isolated-lab", false, "requires independently owned network namespace")
	flag.Parse()
	var err error
	self, e1 := os.Readlink("/proc/self/ns/net")
	host, e2 := os.Readlink("/proc/1/ns/net")
	st, e3 := os.Lstat(*dir)
	if !*isolated || e1 != nil || e2 != nil || self == host || e3 != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		fmt.Fprintln(os.Stderr, "fixture precondition failed")
		os.Exit(2)
	}
	switch *mode {
	case "origin":
		err = origin(*dir)
	case "client":
		b, e := os.ReadFile(*users)
		if e != nil || len(b) > 4096 {
			err = errors.New("credentials_input")
			break
		}
		var u map[string]string
		if e = json.Unmarshal(b, &u); e != nil || u["fixture-one"] == "" {
			err = errors.New("credentials_shape")
			break
		}
		err = client(*dir, *ca, u["fixture-one"], *bulkOuter)
	default:
		err = errors.New("unsupported_mode")
	}
	if err != nil {
		_ = save(filepath.Join(*dir, "failure-"+*mode+".json"), map[string]any{"ok": false, "error_class": "fixture_failed", "utc": stamp()})
		fmt.Fprintln(os.Stderr, "fixture failed")
		os.Exit(1)
	}
}
