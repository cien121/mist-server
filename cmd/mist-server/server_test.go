package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mist/mistcore"
)

var testCID [16]byte
var testKAuth [32]byte

func startTestStack(t *testing.T) *Config {
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
	cfg.Listen = "127.0.0.1:14543"
	cfg.MistBackend = "127.0.0.1:14631"
	cfg.DummyListen = "127.0.0.1:14630"
	cfg.Accounts = accPath
	cfg.Routes = map[string]string{"other.example.com": "127.0.0.1:14630"}

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

func tlsDial(t *testing.T, addr, sni string) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: sni})
	if err != nil {
		t.Fatalf("tls dial %s: %v", addr, err)
	}
	return c
}

// clientAuth performs AUTH and returns session keys + ids.
func clientAuth(t *testing.T, tc *tls.Conn) (kC2S, kS2C [32]byte, connID [16]byte, tok [32]byte, cliEphPriv [32]byte, cliEphPub [32]byte) {
	t.Helper()
	wire, ephPub, ephPriv, err := mistcore.BuildAUTH(testCID, &testKAuth, 0x01, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := tc.Write(wire); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, mistcore.AuthOKWireLen)
	tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(tc, resp); err != nil {
		t.Fatalf("read AUTH_OK: %v", err)
	}
	okr, err := mistcore.ParseAuthOK(resp, &testKAuth)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := mistcore.X25519Shared(&ephPriv, &okr.SrvEphPub)
	if err != nil {
		t.Fatal(err)
	}
	kC2S, kS2C = mistcore.DeriveSessionKeys(ephPub, okr.SrvEphPub, shared)
	tc.SetDeadline(time.Time{})
	return kC2S, kS2C, okr.ConnID, okr.ResumeTok, ephPriv, ephPub
}

func openEchoStream(t *testing.T, sess *mistcore.Session, target string) *mistcore.Stream {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(target)
	var atyp byte
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp, addr = mistcore.ATypIPv4, []byte(ip4)
		} else {
			atyp, addr = mistcore.ATypIPv6, []byte(ip.To16())
		}
	} else {
		atyp, addr = mistcore.ATypDomain, []byte(host)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	st, err := sess.OpenStream(mistcore.EncodeConnectReq(atyp, addr, uint16(port)))
	if err != nil {
		t.Fatal(err)
	}
	code := make([]byte, 1)
	if _, err := io.ReadFull(st, code); err != nil {
		t.Fatalf("read CODE: %v", err)
	}
	if code[0] != 0x00 {
		t.Fatalf("CONNECT failed, code=%d", code[0])
	}
	return st
}

func startEcho(t *testing.T, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
}

func TestEndToEnd(t *testing.T) {
	cfg := startTestStack(t)
	startEcho(t, "127.0.0.1:14599")
	time.Sleep(200 * time.Millisecond)

	// --- A: full AUTH + CONNECT + echo ---
	tc := tlsDial(t, cfg.Listen, "mist.lab")
	kC2S, kS2C, connID, tok, _, _ := clientAuth(t, tc)
	shaper := mistcore.NewShaper(4, 64, 128, 5, 0)
	sess := mistcore.NewSession(mistcore.SessionParams{
		Conn: tc, IsClient: true, KC2S: kC2S, KS2C: kS2C,
		Epoch: 0, Shaper: shaper, MaxStreams: 16,
	})
	st := openEchoStream(t, sess, "127.0.0.1:14599")
	msg := []byte("hello-mist-echo")
	if _, err := st.Write(msg); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(st, back); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(back) != string(msg) {
		t.Fatalf("echo mismatch: %q", back)
	}
	t.Log("A: AUTH+CONNECT+echo OK")

	// --- B: RESUME ---
	rs := &mistcore.ResumeState{
		ConnID: connID, Tok: tok, KC2S: kC2S, KS2C: kS2C,
		Epoch: 0, NextCtr: sess.SendCtr(),
	}
	sess.Close()
	tc2 := tlsDial(t, cfg.Listen, "mist.lab")
	sess2, err := mistcore.ClientResume(tc2, rs, mistcore.NewShaper(0, 0, 0, 0, 0), 16, nil)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	st2 := openEchoStream(t, sess2, "127.0.0.1:14599")
	if _, err := st2.Write(msg); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(st2, back); err != nil {
		t.Fatalf("echo after resume: %v", err)
	}
	if string(back) != string(msg) {
		t.Fatalf("echo mismatch after resume: %q", back)
	}
	t.Log("B: RESUME 1-RTT OK")
	sess2.Close()

	// --- C: decoy web ---
	tc3 := tlsDial(t, cfg.Listen, "mist.lab")
	tc3.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(tc3, "GET / HTTP/1.0\r\n\r\n")
	resp, _ := io.ReadAll(tc3)
	tc3.Close()
	if !strings.Contains(string(resp), "200 OK") || !strings.Contains(string(resp), "Chan's Blog") {
		t.Fatalf("decoy failed: %q", resp[:min(200, len(resp))])
	}
	t.Log("C: decoy 200 OK")

	// --- D: SNI forward to dummy ---
	tc4 := tlsDial(t, cfg.Listen, "other.example.com")
	tc4.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(tc4, "GET / HTTP/1.0\r\n\r\n")
	resp4, _ := io.ReadAll(tc4)
	tc4.Close()
	if !strings.Contains(string(resp4), "MIST-DUMMY-BACKEND") {
		t.Fatalf("dummy forward failed: %q", resp4[:min(200, len(resp4))])
	}
	t.Log("D: SNI forward OK")

	// --- E: bad AUTH -> silent close ---
	tc5 := tlsDial(t, cfg.Listen, "mist.lab")
	tc5.SetDeadline(time.Now().Add(5 * time.Second))
	tc5.Write(mistcore.RandomBytes(89))
	_, err = tc5.Read(make([]byte, 16))
	tc5.Close()
	if err == nil {
		t.Fatal("expected close on bad auth")
	}
	t.Log("E: bad AUTH silently closed")
}


