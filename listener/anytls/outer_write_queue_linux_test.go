//go:build linux

package anytls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	tlsC "github.com/metacubex/mihomo/component/tls"
	client "github.com/metacubex/mihomo/transport/anytls"
	"github.com/metacubex/mihomo/transport/anytls/session"
	"github.com/metacubex/mihomo/transport/vmess"
	M "github.com/metacubex/sing/common/metadata"
	"golang.org/x/sys/unix"
)

func queueOption(t *testing.T, c syscall.Conn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var inner error
	if err = raw.Control(func(fd uintptr) { value, inner = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT) }); err != nil {
		t.Fatal(err)
	}
	if inner != nil {
		t.Fatal(inner)
	}
	return value
}

func TestOuterWriteQueueAcceptedSocketScopeAndCookie(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			address := "127.0.0.1:0"
			if family == "tcp6" {
				address = "[::1]:0"
			}
			raw, err := net.Listen(family, address)
			if err != nil {
				t.Fatal("explicit fixture requires loopback IPv4 and IPv6:", err)
			}
			defer raw.Close()
			beforeNS, err := os.ReadFile("/proc/sys/net/ipv4/tcp_notsent_lowat")
			if err != nil {
				t.Fatal(err)
			}
			listenBefore := queueOption(t, raw.(syscall.Conn))
			peer, err := net.DialTimeout(family, raw.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			peerBefore := queueOption(t, peer.(syscall.Conn))
			wrapped := wrapOuterWriteQueue(raw, true)
			accepted, err := wrapped.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			if queueOption(t, accepted.(syscall.Conn)) != 65536 {
				t.Fatal("accepted option not applied")
			}
			if queueOption(t, raw.(syscall.Conn)) != listenBefore || queueOption(t, peer.(syscall.Conn)) != peerBefore {
				t.Fatal("listener or peer policy changed")
			}
			// Another accepted connection bypasses the wrapper, representing an
			// independent upstream socket under the same namespace policy.
			upstream, err := net.DialTimeout(family, raw.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			other, err := raw.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if queueOption(t, other.(syscall.Conn)) != listenBefore {
				t.Fatal("independent socket inherited accepted-only option")
			}
			afterNS, err := os.ReadFile("/proc/sys/net/ipv4/tcp_notsent_lowat")
			if err != nil || !bytes.Equal(beforeNS, afterNS) {
				t.Fatal("namespace policy changed")
			}
			cookie := session.SocketCookie(accepted)
			tlsConn := tlsC.Server(accepted, &tlsC.Config{})
			wrappedCookie := session.SocketCookie(tlsConn)
			if cookie == nil || wrappedCookie == nil || *cookie != *wrappedCookie || tlsConn.NetConn() != accepted {
				t.Fatal("raw/TLS connection identity changed")
			}
		})
	}
}

type queueFixtureRaw struct {
	controlErr error
	invalidFD  bool
	calls      atomic.Int64
}

func (r *queueFixtureRaw) Control(fn func(uintptr)) error {
	r.calls.Add(1)
	if r.controlErr != nil {
		return r.controlErr
	}
	if r.invalidFD {
		fn(^uintptr(0))
		return nil
	}
	panic("unexpected valid fixture fd")
}
func (*queueFixtureRaw) Read(func(uintptr) bool) error  { panic("read during option setup") }
func (*queueFixtureRaw) Write(func(uintptr) bool) error { panic("write during option setup") }

type queueFixtureConn struct {
	net.Conn
	raw    syscall.RawConn
	err    error
	calls  atomic.Int64
	closes atomic.Int64
}

func (c *queueFixtureConn) SyscallConn() (syscall.RawConn, error) {
	c.calls.Add(1)
	return c.raw, c.err
}
func (c *queueFixtureConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

type queueFixtureListener struct {
	conn   net.Conn
	err    error
	closed atomic.Int64
}

func (l *queueFixtureListener) Accept() (net.Conn, error) { return l.conn, l.err }
func (l *queueFixtureListener) Close() error              { l.closed.Add(1); return nil }
func (*queueFixtureListener) Addr() net.Addr              { return &net.TCPAddr{} }

func TestOuterWriteQueueDefaultAndFailurePreserveConnection(t *testing.T) {
	for _, kind := range []string{"default_off", "no_syscall", "syscall_error", "control_error", "option_error", "nil_raw"} {
		t.Run(kind, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			c := &queueFixtureConn{Conn: a}
			var value net.Conn = c
			switch kind {
			case "no_syscall":
				value = a
			case "syscall_error":
				c.err = io.ErrClosedPipe
			case "control_error":
				c.raw = &queueFixtureRaw{controlErr: io.ErrUnexpectedEOF}
			case "option_error":
				c.raw = &queueFixtureRaw{invalidFD: true}
			}
			base := &queueFixtureListener{conn: value}
			if kind != "default_off" {
				err := setOuterTCPWriteQueue(value)
				if err == nil {
					t.Fatal("socket setup error was swallowed")
				}
				if kind == "syscall_error" && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal("SyscallConn error lost", err)
				}
				if kind == "control_error" && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal("Control error lost", err)
				}
				if kind == "option_error" && !errors.Is(err, unix.EBADF) {
					t.Fatal("setsockopt error lost", err)
				}
			}
			wrapped := wrapOuterWriteQueue(base, kind != "default_off")
			if kind == "default_off" && wrapped != base {
				t.Fatal("default must return original listener")
			}
			got, err := wrapped.Accept()
			if err != nil || got != value || c.closes.Load() != 0 {
				t.Fatal("option failure changed acceptance/connection")
			}
			if kind == "default_off" && c.calls.Load() != 0 {
				t.Fatal("default invoked socket operation")
			}
			wrapped.Close()
			if base.closed.Load() != 1 {
				t.Fatal("Close not delegated")
			}
		})
	}
}

func TestOuterWriteQueueBlockedWarningDoesNotBlockAccept(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var emits atomic.Int64
	entered, release := make(chan struct{}), make(chan struct{})
	w := &outerQueueWarning{emit: func() { emits.Add(1); close(entered); <-release }}
	c := &queueFixtureConn{Conn: a, err: io.ErrClosedPipe}
	l := &outerWriteQueueListener{Listener: &queueFixtureListener{conn: c}, warning: w}
	var workers sync.WaitGroup
	errors := make(chan error, 32)
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			got, err := l.Accept()
			if err != nil || got != c {
				errors <- fmt.Errorf("connection changed")
			}
		}()
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("warning not invoked")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("blocked warning stalled Accept")
	}
	close(release)
	close(errors)
	if emits.Load() != 1 {
		t.Fatal("unbounded warning")
	}
	for err := range errors {
		t.Error(err)
	}
}

func TestOuterWriteQueueCloseUnblocksAccept(t *testing.T) {
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := wrapOuterWriteQueue(raw, true)
	done := make(chan error, 1)
	go func() { _, err := l.Accept(); done <- err }()
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("Accept close error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept survived Close")
	}
}

func TestOuterWriteQueueEnabledTLSAuthenticationAndPayload(t *testing.T) {
	for _, version := range []uint16{tlsC.VersionTLS12, tlsC.VersionTLS13} {
		for _, scheme := range []string{"", "stop=3\n0=30-30\n1=300-300\n2=600-600"} {
			t.Run(fmt.Sprintf("tls_%x_padding_%t", version, scheme != ""), func(t *testing.T) {
				l, h, _, one := acceptanceFixtureTCPWriteQueue(t, version, scheme, true)
				two := client.NewClient(context.Background(), client.ClientConfig{Password: "local-fixture-password-two", Server: M.ParseSocksaddr(l.AddrList()[0].String()), Dialer: new(acceptanceDialer), TLSConfig: &vmess.TLSConfig{Host: "anytls-fixture.test"}})
				defer two.Close()
				for i, c := range []*client.Client{one, two} {
					for n := 0; n < 4; n++ {
						stream, err := c.CreateProxy(context.Background(), M.ParseSocksaddr("payload.test:80"))
						if err != nil {
							t.Fatal(err)
						}
						err = acceptanceEcho(stream, bytes.Repeat([]byte{byte(i), byte(n), 0, 255, 19}, 1024))
						stream.Close()
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				if h.seen.Load() != 8 || h.secondUser.Load() != 4 || h.badMetadata.Load() != 0 {
					t.Fatal("payload or user isolation")
				}
				before := h.seen.Load()
				bad := client.NewClient(context.Background(), client.ClientConfig{Password: "wrong-synthetic-password", Server: M.ParseSocksaddr(l.AddrList()[0].String()), Dialer: new(acceptanceDialer), TLSConfig: &vmess.TLSConfig{Host: "anytls-fixture.test"}})
				defer bad.Close()
				stream, err := bad.CreateProxy(context.Background(), M.ParseSocksaddr("payload.test:80"))
				if stream != nil {
					if err == nil {
						err = acceptanceEcho(stream, []byte("rejected"))
					}
					stream.Close()
				}
				if err == nil || h.seen.Load() != before {
					t.Fatal("wrong credential reached tunnel")
				}
				untrusted, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", l.AddrList()[0].String(), &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "anytls-fixture.test", MinVersion: version, MaxVersion: version})
				if untrusted != nil {
					untrusted.Close()
				}
				var unknown x509.UnknownAuthorityError
				if !errors.As(err, &unknown) {
					t.Fatal("untrusted TLS accepted", err)
				}
				if ca.GetCertPool() == nil {
					t.Fatal("fixture roots missing")
				}
			})
		}
	}
}
