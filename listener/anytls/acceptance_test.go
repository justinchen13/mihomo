package anytls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	client "github.com/metacubex/mihomo/transport/anytls"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	"github.com/metacubex/mihomo/transport/vmess"
	M "github.com/metacubex/sing/common/metadata"
)

type acceptanceDialer struct{ calls atomic.Int64 }

func (d *acceptanceDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, network, destination.String())
	if e == nil {
		d.calls.Add(1)
	}
	return c, e
}
func (d *acceptanceDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("UDP unused")
}

type acceptanceTunnel struct {
	seen        atomic.Int64
	secondUser  atomic.Int64
	badMetadata atomic.Int64
	slowEntered chan struct{}
	slowRelease chan struct{}
	stop        chan struct{}
	response    []byte
}

func (h *acceptanceTunnel) HandleTCPConn(c net.Conn, m *C.Metadata) {
	h.seen.Add(1)
	if m.Host != "payload.test" || m.Type != C.ANYTLS || (m.InUser != "fixture" && m.InUser != "fixture-two") {
		h.badMetadata.Add(1)
	}
	if m.InUser == "fixture-two" {
		h.secondUser.Add(1)
	}
	if m.DstPort == 81 {
		select {
		case h.slowEntered <- struct{}{}:
		default:
		}
		select {
		case <-h.slowRelease:
		case <-h.stop:
			return
		}
	}
	if m.DstPort == 82 {
		return
	}
	if m.DstPort == 83 {
		if _, e := io.ReadFull(c, make([]byte, 1)); e == nil {
			c.Write(h.response)
		}
		return
	}
	io.Copy(c, c)
}
func (*acceptanceTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}
func (*acceptanceTunnel) NatTable() C.NatTable                     { return nil }

func acceptanceCertificate(t *testing.T) (string, string) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(29), Subject: pkix.Name{CommonName: "anytls-fixture.test"}, DNSNames: []string{"anytls-fixture.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.MarshalECPrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}))
}

func acceptanceFixture(t *testing.T, version uint16, paddingScheme string) (*Listener, *acceptanceTunnel, *acceptanceDialer, *client.Client) {
	return acceptanceFixtureTCPWriteQueue(t, version, paddingScheme, false)
}

func acceptanceFixtureTCPWriteQueue(t *testing.T, version uint16, paddingScheme string, enabled bool) (*Listener, *acceptanceTunnel, *acceptanceDialer, *client.Client) {
	t.Helper()
	cert, key := acceptanceCertificate(t)
	if e := ca.AddCertificate(cert); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(ca.ResetCertificate)
	h := &acceptanceTunnel{slowEntered: make(chan struct{}, 1), slowRelease: make(chan struct{}), stop: make(chan struct{})}
	l, e := New(LC.AnyTLSServer{Listen: "127.0.0.1:0", Users: map[string]string{"fixture": "local-fixture-password", "fixture-two": "local-fixture-password-two"}, Certificate: cert, PrivateKey: key, PaddingScheme: paddingScheme, TCPWriteBackpressure: enabled}, h)
	if e != nil {
		t.Fatal(e)
	}
	l.tlsConfig.MinVersion = version
	l.tlsConfig.MaxVersion = version
	d := new(acceptanceDialer)
	c := client.NewClient(context.Background(), client.ClientConfig{Password: "local-fixture-password", Server: M.ParseSocksaddr(l.AddrList()[0].String()), Dialer: d, TLSConfig: &vmess.TLSConfig{Host: "anytls-fixture.test"}, IdleSessionCheckInterval: time.Minute, IdleSessionTimeout: time.Minute})
	t.Cleanup(func() { close(h.stop); c.Close(); l.Close() })
	return l, h, d, c
}

func acceptanceEcho(c net.Conn, payload []byte) error {
	if e := c.SetReadDeadline(time.Now().Add(5 * time.Second)); e != nil {
		return e
	}
	if _, e := c.Write(payload); e != nil {
		return e
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(c, got); e != nil {
		return e
	}
	if !bytes.Equal(got, payload) {
		return errors.New("payload differs")
	}
	return nil
}

func TestAcceptanceListenerPoolTLSAndPadding(t *testing.T) {
	for _, version := range []uint16{tlsC.VersionTLS12, tlsC.VersionTLS13} {
		t.Run(fmt.Sprintf("tls_%x", version), func(t *testing.T) {
			for _, scheme := range []string{"", "stop=3\n0=30-30\n1=300-300\n2=600-600"} {
				t.Run(fmt.Sprintf("custom_padding_%t", scheme != ""), func(t *testing.T) {
					_, h, d, c := acceptanceFixture(t, version, scheme)
					const workers, rounds = 4, 8
					var wg sync.WaitGroup
					errs := make(chan error, workers)
					for w := 0; w < workers; w++ {
						wg.Add(1)
						go func(w int) {
							defer wg.Done()
							for r := 0; r < rounds; r++ {
								conn, e := c.CreateProxy(context.Background(), M.ParseSocksaddr("payload.test:80"))
								if e != nil {
									errs <- e
									return
								}
								payload := bytes.Repeat([]byte{byte(w), byte(r), 0, 255, 73}, 257)
								e = acceptanceEcho(conn, payload)
								conn.Close()
								if e != nil {
									errs <- e
									return
								}
							}
						}(w)
					}
					wg.Wait()
					close(errs)
					for e := range errs {
						t.Error(e)
					}
					if h.seen.Load() != workers*rounds || h.badMetadata.Load() != 0 {
						t.Errorf("handled=%d metadata_errors=%d", h.seen.Load(), h.badMetadata.Load())
					}
					if d.calls.Load() >= workers*rounds {
						t.Error("connection pool never reused TLS session")
					}
					t.Logf("TLS=%x streams=%d TLS_connections=%d custom_padding=%t", version, h.seen.Load(), d.calls.Load(), scheme != "")
				})
			}
		})
	}
}

func TestAcceptanceListenerSlowConnectionDeadlineAndCancellation(t *testing.T) {
	_, h, d, c := acceptanceFixture(t, tlsC.VersionTLS13, "")
	slow, e := c.CreateProxy(context.Background(), M.ParseSocksaddr("payload.test:81"))
	if e != nil {
		t.Fatal(e)
	}
	defer slow.Close()
	select {
	case <-h.slowEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("slow stream not admitted")
	}
	slowPayload := bytes.Repeat([]byte{0x35}, 32768)
	if _, e = slow.Write(slowPayload); e != nil {
		t.Fatal(e)
	}
	fast, e := c.CreateProxy(context.Background(), M.ParseSocksaddr("payload.test:80"))
	if e != nil {
		t.Fatal(e)
	}
	defer fast.Close()
	if e = acceptanceEcho(fast, []byte("independent-connection")); e != nil {
		t.Fatal(e)
	}
	if d.calls.Load() < 2 {
		t.Fatal("fixture did not create independent outer connections")
	}
	fast.SetReadDeadline(time.Now().Add(-time.Second))
	if _, e = fast.Read(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatalf("expired read deadline: %v", e)
	}
	fast.SetDeadline(time.Time{})
	fast.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, e = fast.Write([]byte("must-not-send")); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatalf("expired write entry deadline: %v", e)
	}
	fast.SetDeadline(time.Time{})
	if e = acceptanceEcho(fast, []byte("after-deadline-reset")); e != nil {
		t.Fatal(e)
	}
	close(h.slowRelease)
	slow.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(slowPayload))
	if _, e = io.ReadFull(slow, got); e != nil || !bytes.Equal(got, slowPayload) {
		t.Fatalf("slow resume: %v", e)
	}
	// A live stream's read is interrupted by explicit connection close.
	readDone := make(chan error, 1)
	go func() { _, e := fast.Read(make([]byte, 1)); readDone <- e }()
	fast.Close()
	select {
	case e := <-readDone:
		if e == nil {
			t.Fatal("closed reader returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not cancel reader")
	}
	t.Log("slow receiver isolated by separate outer connection; payload and deadline reset preserved")
}

func TestAcceptanceListenerRejectsWrongCredentialsAndCertificate(t *testing.T) {
	l, h, _, _ := acceptanceFixture(t, tlsC.VersionTLS13, "")
	for _, tc := range []struct{ name, password, host string }{{"bad_password", "incorrect-fixture-password", "anytls-fixture.test"}, {"wrong_hostname", "local-fixture-password", "wrong-name.test"}} {
		t.Run(tc.name, func(t *testing.T) {
			c := client.NewClient(context.Background(), client.ClientConfig{Password: tc.password, Server: M.ParseSocksaddr(l.AddrList()[0].String()), Dialer: new(acceptanceDialer), TLSConfig: &vmess.TLSConfig{Host: tc.host}})
			defer c.Close()
			conn, e := c.CreateProxy(context.Background(), M.ParseSocksaddr("payload.test:80"))
			if conn != nil {
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(time.Second))
				if e == nil {
					e = acceptanceEcho(conn, []byte("rejected"))
				}
			}
			if e == nil {
				t.Fatal("invalid credential/certificate accepted")
			}
		})
	}
	if h.seen.Load() != 0 {
		t.Fatalf("unauthorized streams reached tunnel: %d", h.seen.Load())
	}
	t.Run("untrusted_certificate", func(t *testing.T) {
		conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", l.AddrList()[0].String(), &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "anytls-fixture.test", MinVersion: tls.VersionTLS13})
		if conn != nil {
			conn.Close()
		}
		var unknown x509.UnknownAuthorityError
		if !errors.As(e, &unknown) {
			t.Fatalf("untrusted certificate was not rejected by chain verification: %v", e)
		}
	})
}

func TestAcceptanceListenerSameSessionMultiStream(t *testing.T) {
	l, h, _, _ := acceptanceFixture(t, tlsC.VersionTLS13, "stop=3\n0=30-30\n1=300-300\n2=600-600")
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", l.AddrList()[0].String(), &tls.Config{RootCAs: ca.GetCertPool(), ServerName: "anytls-fixture.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if len(conn.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("TLS peer not verified")
	}
	pw := sha256.Sum256([]byte("local-fixture-password"))
	auth := append(pw[:], 0, 0)
	if _, e = conn.Write(auth); e != nil {
		t.Fatal(e)
	}
	var pad atomic.Pointer[padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	s := session.NewClientSession(conn, &pad)
	defer s.Close()
	s.Run()
	open := func() (*session.Stream, error) {
		stream, e := s.OpenStream()
		if e != nil {
			return nil, e
		}
		if e = M.SocksaddrSerializer.WriteAddrPort(stream, M.ParseSocksaddr("payload.test:80")); e != nil {
			stream.Close()
			return nil, e
		}
		return stream, nil
	}
	first, e := open()
	if e != nil {
		t.Fatal(e)
	}
	if e = acceptanceEcho(first, []byte("settings-and-padding-control")); e != nil {
		t.Fatal(e)
	}
	first.Close()
	if pad.Load().Md5 != l.padding.Load().Md5 {
		t.Fatal("client did not adopt negotiated padding")
	}
	const streams = 8
	opened := make([]*session.Stream, 0, streams)
	for i := 0; i < streams; i++ {
		stream, e := open()
		if e != nil {
			t.Fatal(e)
		}
		opened = append(opened, stream)
	}
	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for i, stream := range opened {
		wg.Add(1)
		go func(i int, stream *session.Stream) {
			defer wg.Done()
			defer stream.Close()
			for r := 0; r < 4; r++ {
				payload := bytes.Repeat([]byte{byte(i), byte(r), 0, 255, 17}, 511)
				if e := acceptanceEcho(stream, payload); e != nil {
					errs <- e
					return
				}
			}
		}(i, stream)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if h.seen.Load() != streams+1 || h.badMetadata.Load() != 0 {
		t.Fatalf("streams=%d metadata_errors=%d", h.seen.Load(), h.badMetadata.Load())
	}
	t.Log("one verified TLS/auth session, eight concurrent streams, 32 exact payload exchanges, negotiated padding confirmed")
}

func TestAcceptanceListenerSeparateUsers(t *testing.T) {
	l, h, _, one := acceptanceFixture(t, tlsC.VersionTLS13, "")
	two := client.NewClient(context.Background(), client.ClientConfig{Password: "local-fixture-password-two", Server: M.ParseSocksaddr(l.AddrList()[0].String()), Dialer: new(acceptanceDialer), TLSConfig: &vmess.TLSConfig{Host: "anytls-fixture.test"}})
	defer two.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i, c := range []*client.Client{one, two} {
		wg.Add(1)
		go func(i int, c *client.Client) {
			defer wg.Done()
			conn, e := c.CreateProxy(context.Background(), M.ParseSocksaddr("payload.test:80"))
			if e != nil {
				errs <- e
				return
			}
			defer conn.Close()
			errs <- acceptanceEcho(conn, bytes.Repeat([]byte{byte(i), 0x97}, 1024))
		}(i, c)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Error(e)
		}
	}
	if h.seen.Load() != 2 || h.secondUser.Load() != 1 || h.badMetadata.Load() != 0 {
		t.Fatalf("user attribution: total=%d second=%d invalid=%d", h.seen.Load(), h.secondUser.Load(), h.badMetadata.Load())
	}
}

func TestAcceptanceCanceledDialDoesNotReachTunnel(t *testing.T) {
	_, h, d, c := acceptanceFixture(t, tlsC.VersionTLS13, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, e := c.CreateProxy(ctx, M.ParseSocksaddr("payload.test:80"))
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(e, context.Canceled) || conn != nil || d.calls.Load() != 0 || h.seen.Load() != 0 {
		t.Fatalf("canceled fresh dial: err=%v returned_conn=%t physical=%d handled=%d", e, conn != nil, d.calls.Load(), h.seen.Load())
	}
}

type acceptancePacedWire struct {
	net.Conn
	enabled atomic.Bool
	entered chan struct{}
	stop    chan struct{}
	once    sync.Once
}

func (c *acceptancePacedWire) Write(data []byte) (int, error) {
	if !c.enabled.Load() {
		return c.Conn.Write(data)
	}
	select {
	case c.entered <- struct{}{}:
	default:
	}
	total := 0
	for len(data) > 0 {
		next := len(data)
		if next > 512 {
			next = 512
		}
		n, e := c.Conn.Write(data[:next])
		total += n
		data = data[n:]
		if e != nil {
			return total, e
		}
		if n != next {
			return total, io.ErrShortWrite
		}
		if len(data) > 0 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-timer.C:
			case <-c.stop:
				timer.Stop()
				return total, net.ErrClosed
			}
		}
	}
	return total, nil
}
func (c *acceptancePacedWire) Close() error {
	c.once.Do(func() { close(c.stop) })
	return c.Conn.Close()
}

// Same production HandleConn authentication, padding negotiation and destination
// routing, with only the underlying server TCP writer paced after TLS setup.
// The test uses the same raw client frame sequence on baseline and candidate;
// client-pool implementation changes do not participate in this comparison.
func TestAcceptanceAuthenticatedProgressingDATAWithQueuedControl(t *testing.T) {
	l, h, _, _ := acceptanceFixture(t, tlsC.VersionTLS13, "")
	h.response = bytes.Repeat([]byte{0, 255, 17, 93, 42, 7, 8, 9}, 4096)
	raw, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	handler, e := sing.NewListenerHandler(sing.ListenerConfig{Tunnel: h, Type: C.ANYTLS})
	if e != nil {
		t.Fatal(e)
	}
	accepted := make(chan *acceptancePacedWire, 1)
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		tcp, e := raw.Accept()
		if e != nil {
			return
		}
		wire := &acceptancePacedWire{Conn: tcp, entered: make(chan struct{}, 1), stop: make(chan struct{})}
		accepted <- wire
		l.HandleConn(tlsC.Server(wire, l.tlsConfig), handler)
	}()
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", raw.Addr().String(), &tls.Config{RootCAs: ca.GetCertPool(), ServerName: "anytls-fixture.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if e != nil {
		t.Fatal(e)
	}
	wire := <-accepted
	defer wire.Close()
	defer conn.Close()
	pw := sha256.Sum256([]byte("local-fixture-password"))
	if _, e = conn.Write(append(pw[:], 0, 0)); e != nil {
		t.Fatal(e)
	}
	// Fixed framing client, independent of the Mihomo client implementation.
	// Commands are the unchanged AnyTLS v2 wire values from frame.go.
	writeFrame := func(command byte, sid uint32, payload []byte) error {
		if len(payload) > 65535 {
			return errors.New("fixture frame too large")
		}
		frame := make([]byte, 7+len(payload))
		frame[0] = command
		binary.BigEndian.PutUint32(frame[1:5], sid)
		binary.BigEndian.PutUint16(frame[5:7], uint16(len(payload)))
		copy(frame[7:], payload)
		_, e := conn.Write(frame)
		return e
	}
	type receivedFrame struct {
		command byte
		sid     uint32
		payload []byte
	}
	readFrame := func() (receivedFrame, error) {
		var header [7]byte
		_, e := io.ReadFull(conn, header[:])
		if e != nil {
			return receivedFrame{}, e
		}
		f := receivedFrame{command: header[0], sid: binary.BigEndian.Uint32(header[1:5]), payload: make([]byte, binary.BigEndian.Uint16(header[5:7]))}
		_, e = io.ReadFull(conn, f.payload)
		return f, e
	}
	open := func(sid uint32, port uint16) error {
		if e := writeFrame(1, sid, nil); e != nil {
			return e
		}
		var addr bytes.Buffer
		if e := M.SocksaddrSerializer.WriteAddrPort(&addr, M.ParseSocksaddrHostPort("payload.test", port)); e != nil {
			return e
		}
		return writeFrame(2, sid, addr.Bytes())
	}
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	if len(conn.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("TLS peer not verified")
	}
	if e = writeFrame(4, 0, []byte("v=2\npadding-md5="+l.padding.Load().Md5)); e != nil {
		t.Fatal(e)
	}
	if e = open(3, 83); e != nil {
		t.Fatal(e)
	}
	settings, opened := false, false
	for !settings || !opened {
		f, e := readFrame()
		if e != nil {
			t.Fatal(e)
		}
		if f.command == 10 {
			settings = true
		}
		if f.command == 7 && f.sid == 3 && len(f.payload) == 0 {
			opened = true
		}
	}
	wire.enabled.Store(true)
	if e = writeFrame(2, 3, []byte{1}); e != nil {
		t.Fatal(e)
	}
	readDone := make(chan error, 1)
	go func() {
		dataOK, controlOK := false, false
		for !dataOK || !controlOK {
			f, e := readFrame()
			if e != nil {
				readDone <- e
				return
			}
			if f.command == 2 && f.sid == 3 {
				if !bytes.Equal(f.payload, h.response) {
					readDone <- errors.New("DATA differs")
					return
				}
				dataOK = true
			}
			if f.command == 7 && f.sid == 5 && len(f.payload) == 0 {
				controlOK = true
			}
		}
		readDone <- nil
	}()
	select {
	case <-wire.entered:
	case <-time.After(time.Second):
		t.Fatal("DATA did not enter paced TLS writer")
	}
	started := time.Now()
	if e = open(5, 80); e != nil {
		t.Fatal(e)
	}
	// Opening this stream makes the server's real HandshakeSuccess queue a
	// control frame behind progressing DATA on the same TLS connection.
	select {
	case e := <-readDone:
		if e != nil {
			t.Fatalf("authenticated DATA interrupted by queued control: %v", e)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("DATA did not finish")
	}
	wire.enabled.Store(false)
	marker := []byte("post-data-control-and-reuse")
	if e = writeFrame(2, 5, marker); e != nil {
		t.Fatal(e)
	}
	for {
		f, e := readFrame()
		if e != nil {
			t.Fatal(e)
		}
		if f.command == 2 && f.sid == 5 {
			if !bytes.Equal(f.payload, marker) {
				t.Fatal("later stream payload differs")
			}
			break
		}
	}
	writeFrame(3, 5, nil)
	conn.Close()
	wire.Close()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("authenticated handler did not exit")
	}
	t.Logf("authenticated exact DATA=%d, queued control and later stream complete in %.3fs", len(h.response), time.Since(started).Seconds())
}
