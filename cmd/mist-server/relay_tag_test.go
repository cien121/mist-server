package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"mist/mistcore"
)

// Distinct ports from server_test.go's startTestStack so both tests can
// run in one go test binary without a bind clash.
func startTagTestStack(t *testing.T) *Config {
	t.Helper()
	copy(testCID[:], mistcore.RandomBytes(16))
	copy(testKAuth[:], mistcore.RandomBytes(32))
	accPath := filepath.Join(t.TempDir(), "accounts.json")
	acc := map[string]string{
		hex.EncodeToString(testCID[:]): base64.StdEncoding.EncodeToString(testKAuth[:]),
	}
	b, _ := json.Marshal(acc)
	os.WriteFile(accPath, b, 0600)

	cfg := defaultConfig()
	cfg.Listen = "127.0.0.1:15543"
	cfg.MistBackend = "127.0.0.1:15631"
	cfg.DummyListen = "127.0.0.1:15630"
	cfg.Accounts = accPath
	cfg.Routes = map[string]string{"other.example.com": "127.0.0.1:15630"}

	accounts := loadAccounts(accPath)
	lookup := func(cid [16]byte) (*[32]byte, bool) {
		ka, ok := accounts[cid]
		if !ok {
			return nil, false
		}
		out := new([32]byte)
		*out = ka
		return out, true
	}
	cert, err := ephemeralCert([]string{cfg.MistDomain, "dummy.local"})
	if err != nil {
		t.Fatal(err)
	}
	rl := newRateLimiter(1000, 1000)
	ms := &mistService{
		cfg: cfg, accounts: accounts, table: newSessionTable(), rl: rl,
		lookup: lookup, cache: mistcore.NewNonceCache(120 * time.Second),
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
	}
	go runDummy(cfg.DummyListen)
	go ms.run()
	go runSplitter(cfg, rl)
	time.Sleep(300 * time.Millisecond)
	return cfg
}

// soReusePort is SO_REUSEPORT on Linux (not exported by syscall here).
const soReusePort = 15

func reuseportControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
	})
}

// startUDPEcho runs a UDP echo server that replies from its own listen
// port via per-peer connected sockets (SO_REUSEPORT). This sandbox
// denies unconnected UDP sendto (EPERM) while connected UDP writes
// pass, and the kernel delivers a peer's packets to its connected
// socket when one exists, so listener + per-peer sockets cooperate:
// the listener handles a peer's first packet, later packets land on
// the peer socket's own read loop.
func startUDPEcho(t *testing.T, addr string) {
	t.Helper()
	lc := net.ListenConfig{Control: reuseportControl}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	laddr := pc.LocalAddr().(*net.UDPAddr)
	var mu sync.Mutex
	peers := map[string]*net.UDPConn{}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range peers {
			c.Close()
		}
	})
	reply := func(data []byte, raddr *net.UDPAddr) {
		mu.Lock()
		c, ok := peers[raddr.String()]
		if !ok {
			d := net.Dialer{LocalAddr: laddr, Control: reuseportControl}
			dc, err := d.DialContext(context.Background(), "udp", raddr.String())
			if err != nil {
				mu.Unlock()
				return
			}
			c = dc.(*net.UDPConn)
			peers[raddr.String()] = c
			go func() {
				buf := make([]byte, 65535)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}()
		}
		mu.Unlock()
		c.Write(data)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			reply(append([]byte{}, buf[:n]...), raddr.(*net.UDPAddr))
		}
	}()
}

func openUDPStream(t *testing.T, sess *mistcore.Session) *mistcore.Stream {
	t.Helper()
	if err := sess.SendControl([]byte{mistcore.MsgUDPAssocReq}); err != nil {
		t.Fatalf("UDP assoc req: %v", err)
	}
	st, err := sess.OpenStream([]byte{})
	if err != nil {
		t.Fatalf("open udp stream: %v", err)
	}
	return st
}

func readDatagramTimeout(t *testing.T, st *mistcore.Stream) []byte {
	t.Helper()
	ch := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		dg, err := st.ReadDatagram()
		if err != nil {
			errCh <- err
			return
		}
		ch <- dg
	}()
	select {
	case dg := <-ch:
		return dg
	case err := <-errCh:
		t.Fatalf("read datagram: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for relay response")
	}
	return nil
}

func TestRelayTaggedDemux(t *testing.T) {
	cfg := startTagTestStack(t)
	startUDPEcho(t, "127.0.0.1:15599")
	startUDPEcho(t, "127.0.0.1:15600")
	time.Sleep(200 * time.Millisecond)

	tc := tlsDial(t, cfg.Listen, "mist.lab")
	kC2S, kS2C, _, _, _, _ := clientAuth(t, tc)
	sess := mistcore.NewSession(mistcore.SessionParams{
		Conn: tc, IsClient: true, KC2S: kC2S, KS2C: kS2C,
		Epoch: 0, Shaper: mistcore.NewShaper(0, 0, 0, 0, 0), MaxStreams: 16,
	})
	defer sess.Close()
	st := openUDPStream(t, sess)

	ipv4 := func(host string, port uint16) (byte, []byte, uint16) {
		return mistcore.ATypIPv4, []byte(net.ParseIP(host).To4()), port
	}
	send := func(tag byte, host string, port uint16, payload string) {
		atyp, addr, p := ipv4(host, port)
		if _, err := st.Write(mistcore.EncodeDatagramTagged(atyp, addr, p, []byte(payload), tag)); err != nil {
			t.Fatalf("write tag %d: %v", tag, err)
		}
	}
	expect := func(wantTag byte, wantPayload string) {
		dg := readDatagramTimeout(t, st)
		_, _, _, data, tag, err := mistcore.DecodeDatagramTagged(dg)
		if err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if tag != wantTag || string(data) != wantPayload {
			t.Fatalf("response tag=%d data=%q, want tag=%d data=%q", tag, data, wantTag, wantPayload)
		}
	}

	// Same target, two tags: responses must carry their own tag, not
	// cross (an untagged single-conn relay would return tag 0 for both).
	send(1, "127.0.0.1", 15599, "tag1-hello")
	expect(1, "tag1-hello")
	send(2, "127.0.0.1", 15599, "tag2-hello")
	expect(2, "tag2-hello")
	send(1, "127.0.0.1", 15599, "tag1-again")
	expect(1, "tag1-again")

	// Two targets interleaved on two tags: each tag keeps its own conn,
	// so all four responses arrive with the right tag and payload.
	send(1, "127.0.0.1", 15599, "a1")
	send(2, "127.0.0.1", 15600, "b1")
	send(1, "127.0.0.1", 15599, "a2")
	send(2, "127.0.0.1", 15600, "b2")
	got := map[string]bool{}
	for i := 0; i < 4; i++ {
		dg := readDatagramTimeout(t, st)
		_, _, _, data, tag, err := mistcore.DecodeDatagramTagged(dg)
		if err != nil {
			t.Fatalf("decode interleaved: %v", err)
		}
		got[string([]byte{tag})+":"+string(data)] = true
	}
	for _, want := range []string{"\x01:a1", "\x02:b1", "\x01:a2", "\x02:b2"} {
		if !got[want] {
			t.Fatalf("missing interleaved response %q, got %v", want, got)
		}
	}

	// Legacy tag==0 path on a fresh stream still works, untagged.
	st0 := openUDPStream(t, sess)
	atyp, addr, p := ipv4("127.0.0.1", 15599)
	if _, err := st0.Write(mistcore.EncodeDatagram(atyp, addr, p, []byte("legacy"))); err != nil {
		t.Fatalf("write legacy: %v", err)
	}
	dg := readDatagramTimeout(t, st0)
	if !bytes.Equal(dg, mistcore.EncodeDatagram(atyp, addr, p, []byte("legacy"))) {
		t.Fatalf("legacy response must be untagged old-format, got %x", dg)
	}
}
