// mist-server: Mist (雾) protocol server with SNI splitter.
//
// Lab defaults: splitter listens on :1443 and routes
//   SNI == mist_domain        -> internal Mist TLS service
//   SNI in routes             -> configured backend (TCP passthrough)
//   other SNI / no SNI        -> default_backend
// Nothing here touches production ports; config is explicit.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"mist/mistcore"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type Config struct {
	Listen         string            `json:"listen"`
	UDPListen      string            `json:"udp_listen"`
	MistDomain     string            `json:"mist_domain"`
	MistBackend    string            `json:"mist_backend"`
	Routes         map[string]string `json:"routes"`
	DefaultBackend string            `json:"default_backend"`
	NoSNIBackend   string            `json:"no_sni_backend"`
	Accounts       string            `json:"accounts"`
	CertFile       string            `json:"cert_file"`
	KeyFile        string            `json:"key_file"`
	MaxConnsPerIP  int               `json:"max_conns_per_ip"`
	NewConnsPerMin int               `json:"new_conns_per_min"`
	DummyListen    string            `json:"dummy_listen"`
	HeartbeatSec   int               `json:"heartbeat_sec"`
	HeavyPackets   int               `json:"shaping_heavy_packets"`
}

func defaultConfig() *Config {
	return &Config{
		Listen:         "0.0.0.0:1443",
		UDPListen:      "0.0.0.0:1443",
		MistDomain:     "mist.lab",
		MistBackend:    "127.0.0.1:14431",
		Routes:         map[string]string{"other.example.com": "127.0.0.1:14430"},
		DefaultBackend: "127.0.0.1:14430",
		NoSNIBackend:   "127.0.0.1:14431",
		Accounts:       "/tmp/mistlab/accounts.json",
		MaxConnsPerIP:  32,
		NewConnsPerMin: 10,
		DummyListen:    "127.0.0.1:14430",
		HeartbeatSec:   mistcore.DefaultHeartbeatSec,
		HeavyPackets:   mistcore.DefaultShapingHeavyPkts,
	}
}

func loadConfig(path string) *Config {
	cfg := defaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("read config: %v", err)
		}
		if err := json.Unmarshal(b, cfg); err != nil {
			log.Fatalf("parse config: %v", err)
		}
	}
	return cfg
}

// ---------------------------------------------------------------------------
// Accounts: hex(CID) -> base64(K_auth)
// ---------------------------------------------------------------------------

func loadAccounts(path string) map[[16]byte][32]byte {
	out := map[[16]byte][32]byte{}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read accounts %s: %v", path, err)
	}
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		log.Fatalf("parse accounts: %v", err)
	}
	for cidHex, kB64 := range raw {
		cb, err := hex.DecodeString(cidHex)
		if err != nil || len(cb) != 16 {
			log.Fatalf("bad cid %q", cidHex)
		}
		kb, err := base64.StdEncoding.DecodeString(kB64)
		if err != nil || len(kb) != 32 {
			log.Fatalf("bad key for %q", cidHex)
		}
		var cid [16]byte
		var ka [32]byte
		copy(cid[:], cb)
		copy(ka[:], kb)
		out[cid] = ka
	}
	log.Printf("loaded %d account(s)", len(out))
	return out
}

// ---------------------------------------------------------------------------
// Rate limiting (SPEC B.2)
// ---------------------------------------------------------------------------

type rateLimiter struct {
	mu       sync.Mutex
	conns    map[string]int
	stamps   map[string][]int64
	maxConns int
	perMin   int
}

func newRateLimiter(maxConns, perMin int) *rateLimiter {
	return &rateLimiter{conns: map[string]int{}, stamps: map[string][]int64{}, maxConns: maxConns, perMin: perMin}
}

func (r *rateLimiter) admit(ip string) bool {
	now := time.Now().Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stamps[ip]
	keep := st[:0]
	for _, ts := range st {
		if now-ts < 60 {
			keep = append(keep, ts)
		}
	}
	if len(keep) >= r.perMin {
		r.stamps[ip] = keep
		return false
	}
	if r.conns[ip] >= r.maxConns {
		r.stamps[ip] = keep
		return false
	}
	r.stamps[ip] = append(keep, now)
	r.conns[ip]++
	return true
}

func (r *rateLimiter) release(ip string) {
	r.mu.Lock()
	if r.conns[ip] > 0 {
		r.conns[ip]--
	}
	r.mu.Unlock()
}

// ---------------------------------------------------------------------------
// SNI parsing (ClientHello only, no decryption)
// ---------------------------------------------------------------------------

func parseSNI(record []byte) string {
	if len(record) < 4 || record[0] != 0x01 {
		return ""
	}
	hsLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if len(record) < 4+hsLen || hsLen < 34 {
		return ""
	}
	p := record[4 : 4+hsLen]
	p = p[2+32:] // legacy_version + random
	if len(p) < 1 {
		return ""
	}
	l := int(p[0]) // session id
	p = p[1:]
	if len(p) < l {
		return ""
	}
	p = p[l:]
	if len(p) < 2 { // cipher suites
		return ""
	}
	l = int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < l {
		return ""
	}
	p = p[l:]
	if len(p) < 1 { // compression methods
		return ""
	}
	l = int(p[0])
	p = p[1:]
	if len(p) < l {
		return ""
	}
	p = p[l:]
	if len(p) < 2 { // extensions
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < extTotal {
		return ""
	}
	p = p[:extTotal]
	for len(p) >= 4 {
		et := binary.BigEndian.Uint16(p[0:2])
		el := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if len(p) < el {
			return ""
		}
		if et == 0x0000 { // server_name
			d := p[:el]
			if len(d) < 2 {
				return ""
			}
			ll := int(binary.BigEndian.Uint16(d))
			d = d[2:]
			if len(d) < ll {
				return ""
			}
			d = d[:ll]
			for len(d) >= 3 {
				nt := d[0]
				nl := int(binary.BigEndian.Uint16(d[1:3]))
				d = d[3:]
				if len(d) < nl {
					return ""
				}
				if nt == 0 {
					return string(d[:nl])
				}
				d = d[nl:]
			}
			return ""
		}
		p = p[el:]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Splitter
// ---------------------------------------------------------------------------

func runSplitter(cfg *Config, rl *rateLimiter) {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("splitter listen %s: %v", cfg.Listen, err)
	}
	log.Printf("splitter listening on %s (mist_domain=%s)", cfg.Listen, cfg.MistDomain)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("splitter accept: %v", err)
			continue
		}
		go handleSplitterConn(c, cfg, rl)
	}
}

func clientIP(c net.Conn) string {
	if h, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		return h
	}
	return c.RemoteAddr().String()
}

func handleSplitterConn(client net.Conn, cfg *Config, rl *rateLimiter) {
	defer client.Close()
	ip := clientIP(client)
	if !rl.admit(ip) {
		return // silent drop (iron rule)
	}
	defer rl.release(ip)

	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x16 { // not a TLS handshake record -> drop silently
		return
	}
	reclen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if reclen < 4 || reclen > 16384 {
		return
	}
	rec := make([]byte, reclen)
	if _, err := io.ReadFull(client, rec); err != nil {
		return
	}
	sni := parseSNI(rec)

	var backend string
	switch {
	case sni == cfg.MistDomain:
		backend = cfg.MistBackend
	case sni != "":
		if b, ok := cfg.Routes[sni]; ok {
			backend = b
		} else {
			backend = cfg.DefaultBackend
		}
	default:
		backend = cfg.NoSNIBackend
	}
	log.Printf("splitter: %s SNI=%q -> %s", ip, sni, backend)

	be, err := net.DialTimeout("tcp", backend, 10*time.Second)
	if err != nil {
		log.Printf("splitter: dial backend %s: %v", backend, err)
		return
	}
	defer be.Close()
	client.SetReadDeadline(time.Time{})
	be.Write(hdr)
	be.Write(rec)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(be, client); wg.Done() }()
	go func() { io.Copy(client, be); wg.Done() }()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Dummy backend (lab only): proves SNI passthrough
// ---------------------------------------------------------------------------

func runDummy(listen string) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("dummy listen %s: %v", listen, err)
	}
	log.Printf("dummy backend on %s", listen)
	cert, err := ephemeralCert([]string{"dummy.local"})
	if err != nil {
		log.Fatalf("dummy cert: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			tc := tls.Server(c, tlsCfg)
			if err := tc.Handshake(); err != nil {
				log.Printf("dummy: tls handshake: %v", err)
				return
			}
			log.Printf("dummy: got TLS connection from %s (SNI=%q)", c.RemoteAddr(), tc.ConnectionState().ServerName)
			br := bufio.NewReader(tc)
			req, _ := http.ReadRequest(br)
			if req != nil {
				log.Printf("dummy: %s %s", req.Method, req.URL.Path)
			}
			body := "MIST-DUMMY-BACKEND"
			fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		}(c)
	}
}

// ---------------------------------------------------------------------------
// Certs
// ---------------------------------------------------------------------------

func ephemeralCert(sans []string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: sans[0]},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// ---------------------------------------------------------------------------
// UDP server (Mist UDP transport, Phase 1)
// ---------------------------------------------------------------------------

// udpServer holds state for the Mist UDP server.
type udpServer struct {
	cfg      *Config
	accounts map[[16]byte][32]byte
	codec    mistcore.InitialCodec
	sessions map[[16]byte]*mistcore.UDPSession // sessionID -> session
	mu       sync.RWMutex
	conn     *net.UDPConn
	// OnUnknownDCID is the h3 fallback hook (Phase 2, §9.1).
	// Called when a short-header packet arrives with an unknown DCID.
	// Phase 4 will implement: forward to real h3 backend by source address
	// (requires per-source forwarding table; h3 backend needs the SNI cert).
	// For now, nil = silent drop (Phase 1 behavior).
	OnUnknownDCID func(pkt []byte, clientAddr *net.UDPAddr)
}

// runUDPServer starts the Mist UDP server.
// Listens on cfg.UDPListen (default 0.0.0.0:1443).
// Handles Initial handshake and data packets (Phase 1: basic, no BBR/reliability).
func runUDPServer(cfg *Config, accounts map[[16]byte][32]byte) {
	addr, err := net.ResolveUDPAddr("udp", cfg.UDPListen)
	if err != nil {
		log.Fatalf("udp resolve %s: %v", cfg.UDPListen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("udp listen %s: %v", cfg.UDPListen, err)
	}
	log.Printf("mist udp listening on %s", cfg.UDPListen)

	srv := &udpServer{
		cfg:      cfg,
		accounts: accounts,
		codec:    &mistcore.RandomCiphertextCodec{},
		sessions: make(map[[16]byte]*mistcore.UDPSession),
		conn:     conn,
	}

	// Safety gate (2026-10-23 review): the Phase 1 random-ciphertext Initial
	// is a DPI fingerprint and must never run on a public network. Refuse to
	// start if the listen address is not loopback/private. This runs before
	// binding so a bad config fails loudly at startup, not silently later.
	if err := mistcore.CheckInitialCodecSafeForAddr(srv.codec, cfg.UDPListen); err != nil {
		log.Printf("FATAL: UDP 安全门拒绝启动")
		log.Printf("原因: %v", err)
		log.Printf("解除方式: (1) 内测请把 udp_listen 改为 127.0.0.1:1443 这类内网地址, " +
			"并用 -tags mist_unsafe_initial 构建; " +
			"(2) 公网部署请等待 Phase 0,换成真 QUIC Initial 实现 (QUICInitialCodec)")
		log.Fatalf("udp safety gate: startup refused")
	}

	// Session cleanup goroutine (idle timeout 5 minutes).
	go srv.cleanupLoop()

	// ACK flush goroutine: the reliability layer only emits ACKs on packet
	// receipt (every 10 packets or 10ms elapsed, checked lazily). Without a
	// periodic flush, the tail of a burst (<10 packets) would never be ACKed
	// until more traffic arrives, and the client's RTO (~RTT on fast paths)
	// would fire spuriously for it. Flush every 10ms to bound ACK delay.
	go srv.ackFlushLoop()

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("udp read: %v", err)
			continue
		}
		// Copy packet (buf is reused).
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go srv.handlePacket(pkt, clientAddr)
	}
}

// cleanupLoop removes idle sessions.
func (s *udpServer) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, sess := range s.sessions {
			// Idle timeout: 5 minutes.
			if now.Sub(sess.LastActive) > 5*time.Minute {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

// ackFlushLoop periodically flushes pending ACKs on all sessions.
// Snapshot under RLock, flush outside the lock (FlushAck's callback writes
// to the socket and must not run while holding the sessions lock).
func (s *udpServer) ackFlushLoop() {
	ticker := time.NewTicker(mistcore.UDPAckTimeout)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.RLock()
		sessList := make([]*mistcore.UDPSession, 0, len(s.sessions))
		for _, sess := range s.sessions {
			sessList = append(sessList, sess)
		}
		s.mu.RUnlock()
		for _, sess := range sessList {
			sess.Rel.FlushAck()
		}
	}
}

// handlePacket processes a single UDP datagram.
func (s *udpServer) handlePacket(pkt []byte, clientAddr *net.UDPAddr) {
	if len(pkt) < 1 {
		return
	}
	// Check packet type: long header (Initial) vs short header (data).
	// Long header: bits 0-1 = 0b11. Short header: bits 0-1 = 0b01.
	if pkt[0]&0xC0 == 0xC0 {
		s.handleInitial(pkt, clientAddr)
	} else if pkt[0]&0xC0 == 0x40 {
		s.handleData(pkt, clientAddr)
	}
	// else: not a QUIC packet, ignore (silent).
}

// handleInitial processes a QUIC Initial packet (handshake).
func (s *udpServer) handleInitial(pkt []byte, clientAddr *net.UDPAddr) {
	// Lookup function for HANDSHAKE_CID.
	// Per UDP-DESIGN.md §5.1: HANDSHAKE_CID = HMAC-SHA256(K_auth, NONCE)[0:16].
	lookup := func(handshakeCID [16]byte, nonce [24]byte) (*[32]byte, [16]byte, bool) {
		for cid, kAuth := range s.accounts {
			mac := hmac.New(sha256.New, kAuth[:])
			mac.Write(nonce[:])
			sum := mac.Sum(nil)
			var expected [16]byte
			copy(expected[:], sum[:16])
			if expected == handshakeCID {
				ka := new([32]byte)
				*ka = kAuth
				return ka, cid, true
			}
		}
		return nil, [16]byte{}, false
	}

	result, err := mistcore.UDPServerHandshake(s.codec, pkt, clientAddr, lookup)
	if err != nil {
		// Silent on failure (anti-probing).
		return
	}

	// Wire reliability callbacks for the data path (lab echo):
	// - OnAckNeeded: ACK received packets so the peer's RTO doesn't fire
	//   spuriously. ACKs go untracked (never ACKed themselves).
	// - OnRetransmit: resend our own lost packets with new packet numbers.
	sess := result.Session
	sess.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		ack := mistcore.EncodeAckFrame(0, largest, ackDelay, ranges)
		resp, err := sess.SealPacketUntracked(mistcore.DirS2C, [][]byte{ack})
		if err == nil {
			s.conn.WriteToUDP(resp, sess.RemoteAddr)
		}
	}
	sess.Rel.OnRetransmit = func(frames [][]byte) {
		resp, err := sess.SealPacket(mistcore.DirS2C, frames)
		if err == nil {
			s.conn.WriteToUDP(resp, sess.RemoteAddr)
		}
	}

	// Store session.
	s.mu.Lock()
	s.sessions[result.Session.SessionID] = result.Session
	s.mu.Unlock()

	// Send AUTH_OK response.
	_, err = s.conn.WriteToUDP(result.Response, clientAddr)
	if err != nil {
		log.Printf("udp write AUTH_OK: %v", err)
	}
}

// handleData processes a QUIC short header packet (data).
func (s *udpServer) handleData(pkt []byte, clientAddr *net.UDPAddr) {
	if len(pkt) < mistcore.QUICShortHeaderLen {
		return
	}
	// Extract DCID (bytes 1-8) to find session.
	var dcid [8]byte
	copy(dcid[:], pkt[1:9])

	// Find session by DCID (first 8 bytes of session ID).
	s.mu.RLock()
	var session *mistcore.UDPSession
	for _, sess := range s.sessions {
		if sess.SessionID8() == dcid {
			session = sess
			break
		}
	}
	s.mu.RUnlock()

	if session == nil {
		// Unknown DCID: h3 fallback hook (Phase 2, §9.1).
		// Phase 4 will forward to real h3 backend here.
		if s.OnUnknownDCID != nil {
			s.OnUnknownDCID(pkt, clientAddr)
		}
		return // Silent drop if no hook.
	}

	// Update remote address (for migration).
	// For Phase 1: just update it directly (no PATH_CHALLENGE yet).
	// Phase 2 will add proper path validation.
	session.RemoteAddr = clientAddr

	// Decrypt and process frames.
	// Direction: client → server.
	frames, _, err := session.OpenPacket(mistcore.DirC2S, pkt)
	if err != nil {
		return // Decrypt failed, silent drop.
	}

	// Phase 1: basic frame handling.
	// For now, just acknowledge receipt by updating last-active.
	// Full proxy logic (CONNECT, STREAM routing) will be added in Phase 3
	// when the Xray client is implemented.
	for _, f := range frames {
		switch f.Type {
		case mistcore.UDPFramePing:
			// For testing: if we receive a PING, send back a PONG.
			pong := mistcore.EncodeUDPFrame(mistcore.UDPFramePong, 0, nil)
			resp, err := session.SealPacket(mistcore.DirS2C, [][]byte{pong})
			if err == nil {
				s.conn.WriteToUDP(resp, clientAddr)
			}
		case mistcore.UDPFrameAck:
			// Process peer ACKs so our tracked sent-packets get cleared
			// (prevents spurious RTO retransmits of echoes).
			largest, ackDelay, ranges, err := mistcore.DecodeAckFrame(f.Payload)
			if err == nil {
				session.Rel.ProcessAck(largest, ackDelay, ranges)
			}
		case mistcore.UDPFrameStream:
			// Lab echo (mist-udp-test): reflect the STREAM frame back
			// verbatim (same SID, offset, data).
			echo := mistcore.EncodeUDPFrame(mistcore.UDPFrameStream, f.SID, f.Payload)
			resp, err := session.SealPacket(mistcore.DirS2C, [][]byte{echo})
			if err == nil {
				s.conn.WriteToUDP(resp, clientAddr)
			}
		case mistcore.UDPFrameSyn:
			// Stream open noted; no reply needed in echo mode.
		case mistcore.UDPFrameFin:
			// Echo FIN back (same SID, FINAL_SIZE) for a clean close.
			echo := mistcore.EncodeUDPFrame(mistcore.UDPFrameFin, f.SID, f.Payload)
			resp, err := session.SealPacket(mistcore.DirS2C, [][]byte{echo})
			if err == nil {
				s.conn.WriteToUDP(resp, clientAddr)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Session table (server side)
// ---------------------------------------------------------------------------

type serverSession struct {
	connID  [16]byte
	tok     [32]byte
	kC2S    [32]byte
	kS2C    [32]byte
	epoch   uint32
	recvCtr uint32 // last accepted receive counter (resume window base)
	sess    *mistcore.Session
	lastAct int64 // unix nano, atomic
	ip      string
	cidHex  string

	mu          sync.Mutex // guards sess/resumeTimer
	resumeTimer *time.Timer

	udpMu     sync.Mutex
	expectUDP bool
}

// resumeWindowSec: how long a dead session stays resumable (SPEC 10.3).
const resumeWindowSec = 300

func (ss *serverSession) touch() { atomic.StoreInt64(&ss.lastAct, time.Now().UnixNano()) }

type sessionTable struct {
	mu sync.RWMutex
	m  map[[16]byte]*serverSession
}

func newSessionTable() *sessionTable { return &sessionTable{m: map[[16]byte]*serverSession{}} }

func (t *sessionTable) add(s *serverSession) {
	t.mu.Lock()
	t.m[s.connID] = s
	t.mu.Unlock()
}

func (t *sessionTable) remove(connID [16]byte) {
	t.mu.Lock()
	delete(t.m, connID)
	t.mu.Unlock()
}

// tryResume scans recent sessions for one whose old keys decrypt frame as a
// RESUME control message. Returns the session and the client's new epoch.
func (t *sessionTable) tryResume(frame []byte) (*serverSession, uint32) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := 0
	for _, s := range t.m {
		n++
		if n > 64 {
			break
		}
		// ctr starts at s.recvCtr: the client's next send counter equals the
		// number of frames the server has received so far.
		s.mu.Lock()
		hit, newEpoch := false, uint32(0)
		for ctr := s.recvCtr; ctr < s.recvCtr+64; ctr++ {
			df, err := mistcore.DecodeFrame(frame, &s.kC2S, s.epoch, mistcore.DirC2S, ctr)
			if err != nil {
				continue
			}
			if df.SidFlags != mistcore.SidControl {
				break
			}
			cid, tok, ne, ok := mistcore.ParseResumeMsg(df.Payload)
			if !ok || cid != s.connID || tok != s.tok || ne != s.epoch+1 {
				break
			}
			s.recvCtr = ctr
			hit, newEpoch = true, ne
			break
		}
		s.mu.Unlock()
		if hit {
			return s, newEpoch
		}
	}
	return nil, 0
}

// ---------------------------------------------------------------------------
// Mist TLS service
// ---------------------------------------------------------------------------

type mistService struct {
	cfg      *Config
	accounts map[[16]byte][32]byte
	table    *sessionTable
	rl       *rateLimiter
	lookup   func(cid [16]byte) (*[32]byte, bool)
	cache    *mistcore.NonceCache
	tlsCfg   *tls.Config
}

func (m *mistService) run() {
	ln, err := net.Listen("tcp", m.cfg.MistBackend)
	if err != nil {
		log.Fatalf("mist backend listen %s: %v", m.cfg.MistBackend, err)
	}
	log.Printf("mist TLS service on %s", m.cfg.MistBackend)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("mist accept: %v", err)
			continue
		}
		go m.handleConn(c)
	}
}

// prefixConn replays already-read bytes before the underlying conn.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH "}

func looksLikeHTTP(b []byte) bool {
	for _, mth := range httpMethods {
		if len(b) >= len(mth) && string(b[:len(mth)]) == mth {
			return true
		}
	}
	return false
}

func (m *mistService) handleConn(raw net.Conn) {
	defer raw.Close()
	ip := clientIP(raw)
	if !m.rl.admit(ip) {
		return
	}
	defer m.rl.release(ip)

	var tc net.Conn = raw
	if os.Getenv("MIST_PLAINTEXT") == "" {
		tlsConn := tls.Server(raw, m.tlsCfg)
		tlsConn.SetReadDeadline(time.Now().Add(15 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			return // silent
		}
		tc = tlsConn
	}

	// Read first application data: 89 bytes (AUTH), a framed RESUME
	// (77..336 bytes), or an HTTP request (decoy).
	br := bufio.NewReader(tc)
	first := make([]byte, 0, mistcore.AuthWireLen)
	tmp := make([]byte, 4096)
	tc.SetReadDeadline(time.Now().Add(8 * time.Second))
	for len(first) < mistcore.AuthWireLen {
		n, err := br.Read(tmp)
		if n > 0 {
			first = append(first, tmp[:n]...)
		}
		if err != nil || looksLikeHTTP(first) {
			break
		}
		if fl := mistcore.FrameWireLen(first); fl >= 77 && fl <= 336 && fl <= len(first) {
			break // complete RESUME-candidate frame buffered
		}
	}
	tc.SetReadDeadline(time.Time{})

	if looksLikeHTTP(first) {
		// Hand br's buffered bytes to the prefixConn so serveDecoy sees the
		// full request.
		prefix := append([]byte{}, first...)
		if br.Buffered() > 0 {
			extra := make([]byte, br.Buffered())
			br.Read(extra)
			prefix = append(prefix, extra...)
		}
		m.serveDecoy(&prefixConn{Conn: tc, prefix: prefix})
		return
	}

	// RESUME attempt (only if the bytes plausibly hold a full frame).
	if fl := mistcore.FrameWireLen(first); fl >= 77 && fl <= 336 {
		if fl > len(first) {
			tc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			for len(first) < fl {
				n, err := br.Read(tmp)
				if n > 0 {
					first = append(first, tmp[:n]...)
				}
				if err != nil {
					break
				}
			}
			tc.SetReadDeadline(time.Time{})
		}
		if fl <= len(first) {
			if ss, newEpoch := m.table.tryResume(first[:fl]); ss != nil {
				rest := append([]byte{}, first[fl:]...)
				if br.Buffered() > 0 {
					extra := make([]byte, br.Buffered())
					br.Read(extra)
					rest = append(rest, extra...)
				}
				m.serveResume(&prefixConn{Conn: tc, prefix: rest}, ss, newEpoch)
				return
			}
		}
	}

	// AUTH path: top up to 89 bytes if we broke out early.
	if len(first) < mistcore.AuthWireLen {
		tc.SetReadDeadline(time.Now().Add(3 * time.Second))
		for len(first) < mistcore.AuthWireLen {
			n, err := br.Read(tmp)
			if n > 0 {
				first = append(first, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		tc.SetReadDeadline(time.Time{})
	}
	if len(first) < mistcore.AuthWireLen {
		return
	}
	ar, err := mistcore.ParseAUTH(first[:mistcore.AuthWireLen], m.lookup, time.Now(), mistcore.DefaultAuthWindowSec, m.cache)
	rest := append([]byte{}, first[mistcore.AuthWireLen:]...)
	if br.Buffered() > 0 {
		extra := make([]byte, br.Buffered())
		br.Read(extra)
		rest = append(rest, extra...)
	}
	if err != nil {
		return // silent close (iron rule); not HTTP, not AUTH, not RESUME
	}
	m.serveMist(&prefixConn{Conn: tc, prefix: rest}, ar, ip)
}

// serveResume rebinds a session to a new transport (SPEC 10.2/10.3).
func (m *mistService) serveResume(c net.Conn, ss *serverSession, newEpoch uint32) {
	oldSess := ss.sess
	// RESUME_OK is handshake traffic, not session traffic: send it directly
	// with ctr=0 so both sides start the new session with counters at 0.
	okFrame, err := mistcore.EncodeFrame(mistcore.SidControl, mistcore.BuildResumeOKMsg(newEpoch), 0, &ss.kS2C, newEpoch, mistcore.DirS2C, 0)
	if err != nil {
		return
	}
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(okFrame); err != nil {
		return
	}
	c.SetDeadline(time.Time{})

	ss.epoch = newEpoch
	ss.recvCtr = 0
	shaper := mistcore.NewShaper(m.cfg.HeavyPackets, mistcore.DefaultShapingPadMin, mistcore.DefaultShapingPadMax, mistcore.DefaultShapingJitterMs, mistcore.DefaultShapingTailPad)
	sess := mistcore.NewSession(mistcore.SessionParams{
		Conn: c, IsClient: false, KC2S: ss.kC2S, KS2C: ss.kS2C,
		Epoch: newEpoch, Shaper: shaper, MaxStreams: mistcore.DefaultMaxStreams,
		OnAccept:  func(st *mistcore.Stream) { m.onStream(ss, st) },
		OnControl: func(typ byte, body []byte) { m.onControl(ss, typ, body) },
	})
	ss.mu.Lock()
	if ss.resumeTimer != nil {
		ss.resumeTimer.Stop()
		ss.resumeTimer = nil
	}
	ss.sess = sess
	ss.mu.Unlock()
	ss.touch()
	log.Printf("mist: RESUME ok conn=%x epoch=%d from %s", ss.connID[:4], newEpoch, ss.ip)
	m.watchIdle(ss, sess)
	// Old transport: 5s grace, then close.
	go func() {
		time.Sleep(5 * time.Second)
		if oldSess != nil {
			oldSess.Close()
		}
	}()
	sess.Wait()
	m.sessionDone(ss, sess)
}

// sessionDone suspends the session instead of removing it immediately,
// leaving a resume window (SPEC 10.3). The table entry is removed only if
// no RESUME rebinds within resumeWindowSec.
func (m *mistService) sessionDone(ss *serverSession, sess *mistcore.Session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.sess != sess {
		return // superseded by a resumed generation
	}
	ss.sess = nil
	if ss.resumeTimer != nil {
		ss.resumeTimer.Stop()
	}
	ss.resumeTimer = time.AfterFunc(resumeWindowSec*time.Second, func() {
		ss.mu.Lock()
		defer ss.mu.Unlock()
		if ss.sess == nil {
			m.table.remove(ss.connID)
			mistcore.Zeroize(ss.kC2S[:])
			mistcore.Zeroize(ss.kS2C[:])
		}
	})
}

// watchIdle reclaims sessions idle for 300s (SPEC 10.4, B.2).
func (m *mistService) watchIdle(ss *serverSession, sess *mistcore.Session) {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			if sess.IsClosed() {
				return
			}
			if time.Now().UnixNano()-atomic.LoadInt64(&ss.lastAct) > 300*1e9 {
				sess.Close()
				return
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// Decoy web (guest mode)
// ---------------------------------------------------------------------------

func (m *mistService) serveDecoy(c net.Conn) {
	// Splice guest traffic to the local nginx decoy website (127.0.0.1:14445).
	// c is a prefixConn replaying the already-read HTTP request bytes.
	be, err := net.DialTimeout("tcp", "127.0.0.1:14445", 5*time.Second)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		c.Close()
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(be, c); be.Close(); c.Close(); wg.Done() }()
	go func() { io.Copy(c, be); be.Close(); c.Close(); wg.Done() }()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Authenticated session
// ---------------------------------------------------------------------------

func (m *mistService) serveMist(c net.Conn, ar *mistcore.AuthResult, ip string) {
	srvPriv, srvPub, err := mistcore.X25519Keypair()
	if err != nil {
		return
	}
	defer mistcore.Zeroize(srvPriv[:])
	shared, err := mistcore.X25519Shared(&srvPriv, &ar.EphPub)
	if err != nil {
		return
	}
	defer mistcore.Zeroize(shared[:])
	kC2S, kS2C := mistcore.DeriveSessionKeys(ar.EphPub, srvPub, shared)

	kAuth, ok := m.lookup(ar.CID)
	if !ok {
		return
	}
	var connID [16]byte
	copy(connID[:], mistcore.RandomBytes(16))
	var tok [32]byte
	copy(tok[:], mistcore.RandomBytes(32))
	okWire, err := mistcore.BuildAuthOK(kAuth, srvPub, connID, tok, mistcore.DefaultMaxStreams, uint16(m.cfg.HeartbeatSec), time.Now())
	if err != nil {
		return
	}
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(okWire); err != nil {
		return
	}
	c.SetDeadline(time.Time{})

	cidHex := hex.EncodeToString(ar.CID[:])
	log.Printf("mist: AUTH ok cid=%s.. from %s", cidHex[:8], ip)

	ss := &serverSession{
		connID: connID, tok: tok, kC2S: kC2S, kS2C: kS2C,
		epoch: 0, ip: ip, cidHex: cidHex,
	}
	m.table.add(ss)

	shaper := mistcore.NewShaper(m.cfg.HeavyPackets, mistcore.DefaultShapingPadMin, mistcore.DefaultShapingPadMax, mistcore.DefaultShapingJitterMs, mistcore.DefaultShapingTailPad)
	sess := mistcore.NewSession(mistcore.SessionParams{
		Conn: c, IsClient: false, KC2S: kC2S, KS2C: kS2C,
		Epoch: 0, Shaper: shaper, MaxStreams: mistcore.DefaultMaxStreams,
		OnAccept:  func(st *mistcore.Stream) { m.onStream(ss, st) },
		OnControl: func(typ byte, body []byte) { m.onControl(ss, typ, body) },
	})
	defer m.sessionDone(ss, sess)
	ss.sess = sess
	ss.touch()

	m.watchIdle(ss, sess)

	sess.Wait()
	log.Printf("mist: session %x closed", connID[:4])
}

// onControl handles control messages the mux doesn't handle internally.
func (m *mistService) onControl(ss *serverSession, typ byte, body []byte) {
	if typ == mistcore.MsgUDPAssocReq {
		ss.udpMu.Lock()
		ss.expectUDP = true
		ss.udpMu.Unlock()
	}
}

func (m *mistService) onStream(ss *serverSession, st *mistcore.Stream) {
	ss.touch()
	ss.udpMu.Lock()
	udp := ss.expectUDP
	ss.expectUDP = false
	ss.udpMu.Unlock()
	if udp {
		go m.relayUDP(ss, st)
		return
	}
	go m.handleConnect(ss, st)
}

// handleConnect reads the CONNECT request, dials the target, pipes data.
func (m *mistService) handleConnect(ss *serverSession, st *mistcore.Stream) {
	defer st.Close()
	buf := make([]byte, 0, 300)
	tmp := make([]byte, 300)
	for {
		n, err := st.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		atyp, addr, port, derr := mistcore.DecodeConnectReq(buf)
		if derr == nil {
			m.dialAndPipe(ss, st, atyp, addr, port)
			return
		}
		if err != nil || len(buf) > 300 {
			return
		}
	}
}

func targetAddr(atyp byte, addr []byte, port uint16) string {
	switch atyp {
	case mistcore.ATypIPv4, mistcore.ATypIPv6:
		return fmt.Sprintf("%s:%d", net.IP(addr).String(), port)
	case mistcore.ATypDomain:
		return fmt.Sprintf("%s:%d", string(addr), port)
	}
	return ""
}

func (m *mistService) dialAndPipe(ss *serverSession, st *mistcore.Stream, atyp byte, addr []byte, port uint16) {
	target := targetAddr(atyp, addr, port)
	if target == "" {
		st.Write([]byte{0x01})
		return
	}
	up, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		log.Printf("mist: dial %s: %v", target, err)
		st.Write([]byte{0x01})
		return
	}
	defer up.Close()
	if _, err := st.Write([]byte{0x00}); err != nil {
		return
	}
	log.Printf("mist: stream %d -> %s", st.SID(), target)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(up, st); wg.Done() }()
	go func() { io.Copy(st, up); wg.Done() }()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// UDP relay (SPEC 9.4, v0.1 basic)
// ---------------------------------------------------------------------------

func (m *mistService) relayUDP(ss *serverSession, st *mistcore.Stream) {
	defer st.Close()
	var uc *net.UDPConn
	defer func() {
		if uc != nil {
			uc.Close()
		}
	}()
	var curTarget string
	for {
		dg, err := st.ReadDatagram()
		if err != nil {
			return
		}
		ss.touch()
		atyp, addr, port, data, err := mistcore.DecodeDatagram(dg)
		if err != nil {
			continue
		}
		target := targetAddr(atyp, addr, port)
		if target == "" {
			continue
		}
		if uc == nil || target != curTarget {
			if uc != nil {
				uc.Close()
			}
			raddr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				continue
			}
			uc, err = net.DialUDP("udp", nil, raddr)
			if err != nil {
				uc = nil
				continue
			}
			curTarget = target
			go m.udpReadLoop(ss, st, uc)
		}
		uc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := uc.Write(data); err != nil {
			return
		}
	}
}

func (m *mistService) udpReadLoop(ss *serverSession, st *mistcore.Stream, uc *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		uc.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, raddr, err := uc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		ss.touch()
		var atyp byte
		var addr []byte
		if ip4 := raddr.IP.To4(); ip4 != nil {
			atyp, addr = mistcore.ATypIPv4, []byte(ip4)
		} else {
			atyp, addr = mistcore.ATypIPv6, []byte(raddr.IP.To16())
		}
		dg := mistcore.EncodeDatagram(atyp, addr, uint16(raddr.Port), buf[:n])
		if _, err := st.Write(dg); err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

// buildCommit is stamped at build time via -ldflags "-X main.buildCommit=<sha>".
// 联调基线: mist-udp-pre-integration (xray-core ccc73db8).
var buildCommit = "dev"

func main() {
	cfgPath := flag.String("config", "", "path to JSON config (default: built-in lab defaults)")
	showVersion := flag.Bool("version", false, "print build commit and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mist-server build %s\n", buildCommit)
		os.Exit(0)
	}
	log.Printf("mist-server starting (build %s)", buildCommit)

	cfg := loadConfig(*cfgPath)
	accounts := loadAccounts(cfg.Accounts)
	lookup := func(cid [16]byte) (*[32]byte, bool) {
		ka, ok := accounts[cid]
		if !ok {
			return nil, false
		}
		out := new([32]byte)
		*out = ka
		return out, true
	}

	var cert tls.Certificate
	var err error
	if cfg.CertFile != "" {
		cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			log.Fatalf("load cert: %v", err)
		}
		log.Printf("using cert %s", cfg.CertFile)
	} else {
		cert, err = ephemeralCert([]string{cfg.MistDomain, "dummy.local"})
		if err != nil {
			log.Fatalf("ephemeral cert: %v", err)
		}
		log.Printf("WARNING: ephemeral self-signed cert (lab only)")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	// ECH: load keys if available (RFC 9849)
	if echKeys := loadECHKeys("/opt/mist/ech-keys.json"); echKeys != nil {
		tlsCfg.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{
			Config:      echKeys.Config,
			PrivateKey:  echKeys.PrivateKey,
			SendAsRetry: true,
		}}
		log.Printf("ECH enabled (public_name=%s)", echKeys.PublicName)
	}

	rl := newRateLimiter(cfg.MaxConnsPerIP, cfg.NewConnsPerMin)
	ms := &mistService{
		cfg: cfg, accounts: accounts, table: newSessionTable(), rl: rl,
		lookup: lookup, cache: mistcore.NewNonceCache(mistcore.DefaultNonceCacheTTL * time.Second),
		tlsCfg: tlsCfg,
	}
	if cfg.DummyListen != "" {
		go runDummy(cfg.DummyListen)
	}
	go ms.run()
	// UDP server for Mist UDP transport (Phase 1).
	if cfg.UDPListen != "" {
		go runUDPServer(cfg, accounts)
	}
	runSplitter(cfg, rl)
}
