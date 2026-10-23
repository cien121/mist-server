// mist-udp-test: Standalone Mist UDP handshake + data path test client.
//
// Lab only: requires `-tags mist_unsafe_initial` (uses RandomCiphertextCodec).
// Connects to a Mist UDP server, performs handshake, sends PING, verifies PONG.
//
// Usage: mist-udp-test -server 10.8.0.1:1443 -cid <hex> -key <base64>
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"mist/mistcore"
)

func main() {
	serverAddr := flag.String("server", "10.8.0.1:1443", "server UDP address")
	cidHex := flag.String("cid", "", "client CID (hex, 16 bytes)")
	keyB64 := flag.String("key", "", "K_auth (base64, 32 bytes)")
	flag.Parse()

	if *cidHex == "" || *keyB64 == "" {
		fmt.Fprintln(os.Stderr, "need -cid and -key")
		os.Exit(1)
	}

	// Parse CID.
	cidBytes, err := hex.DecodeString(*cidHex)
	if err != nil || len(cidBytes) != 16 {
		fmt.Fprintln(os.Stderr, "bad cid")
		os.Exit(1)
	}
	var cid [16]byte
	copy(cid[:], cidBytes)

	// Parse K_auth.
	keyBytes, err := base64.StdEncoding.DecodeString(*keyB64)
	if err != nil || len(keyBytes) != 32 {
		fmt.Fprintln(os.Stderr, "bad key")
		os.Exit(1)
	}
	var kAuth [32]byte
	copy(kAuth[:], keyBytes)

	// Resolve server.
	udpAddr, err := net.ResolveUDPAddr("udp", *serverAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}

	// Create unconnected UDP socket.
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("=== Mist UDP Test ===\n")
	fmt.Printf("Server: %s\n", *serverAddr)
	fmt.Printf("CID: %s\n", *cidHex)

	// --- Handshake ---
	hsStart := time.Now()

	// Generate ephemeral keypair.
	ephPriv, ephPub, err := mistcore.X25519Keypair()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keypair:", err)
		os.Exit(1)
	}

	// Build AUTH plaintext: [VER(1)][TS(8)][EPH_PUB(32)][FEAT(1)][MODE(1)][RSVD(2)]
	authPlain := make([]byte, 45)
	authPlain[0] = 0x02 // VER = UDP
	binary.BigEndian.PutUint64(authPlain[1:9], uint64(time.Now().Unix()))
	copy(authPlain[9:41], ephPub[:])

	// Encrypt with K_auth.
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		fmt.Fprintln(os.Stderr, "nonce:", err)
		os.Exit(1)
	}
	// HANDSHAKE_CID = HMAC-SHA256(K_auth, NONCE)[0:16]
	mac := hmac.New(sha256.New, kAuth[:])
	mac.Write(nonce[:])
	var handshakeCID [16]byte
	copy(handshakeCID[:], mac.Sum(nil)[:16])

	ciphertext, err := mistcore.UDPSeal(&kAuth, nonce, authPlain, handshakeCID[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "seal:", err)
		os.Exit(1)
	}

	// Wire: [HANDSHAKE_CID(16)][NONCE(24)][CIPHERTEXT]
	authWire := make([]byte, 0, 16+24+len(ciphertext))
	authWire = append(authWire, handshakeCID[:]...)
	authWire = append(authWire, nonce[:]...)
	authWire = append(authWire, ciphertext...)

	// Generate SCID.
	var scid [8]byte
	if _, err := rand.Read(scid[:]); err != nil {
		fmt.Fprintln(os.Stderr, "scid:", err)
		os.Exit(1)
	}
	var dcid [8]byte // zeros for Initial

	codec := &mistcore.RandomCiphertextCodec{}
	initial, err := codec.SealInitial(authWire, dcid, scid, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seal initial:", err)
		os.Exit(1)
	}

	fmt.Printf("Sending Initial (%d bytes)...\n", len(initial))

	// Send with retransmit (4 attempts, 1s each).
	var response []byte
	retransmits := 0
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			retransmits++
			// New NONCE and SCID per retransmit.
			if _, err := rand.Read(nonce[:]); err != nil {
				break
			}
			if _, err := rand.Read(scid[:]); err != nil {
				break
			}
			mac := hmac.New(sha256.New, kAuth[:])
			mac.Write(nonce[:])
			copy(handshakeCID[:], mac.Sum(nil)[:16])
			ciphertext, _ = mistcore.UDPSeal(&kAuth, nonce, authPlain, handshakeCID[:])
			authWire = authWire[:0]
			authWire = append(authWire, handshakeCID[:]...)
			authWire = append(authWire, nonce[:]...)
			authWire = append(authWire, ciphertext...)
			initial, _ = codec.SealInitial(authWire, dcid, scid, 0)
			fmt.Printf("  retransmit #%d\n", attempt)
		}
		if _, err := conn.WriteToUDP(initial, udpAddr); err != nil {
			fmt.Fprintln(os.Stderr, "send:", err)
			os.Exit(1)
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 2048)
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil {
			response = buf[:n]
			break
		}
	}
	if response == nil {
		fmt.Fprintln(os.Stderr, "FAIL: handshake timeout (4 attempts)")
		os.Exit(1)
	}

	hsElapsed := time.Since(hsStart)
	fmt.Printf("Got AUTH_OK response (%d bytes) in %v (retransmits: %d)\n",
		len(response), hsElapsed, retransmits)

	// Parse AUTH_OK.
	authOKWire, respDCID, _, _, err := codec.OpenInitialResponse(response)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse auth_ok:", err)
		os.Exit(1)
	}
	if respDCID != scid {
		fmt.Fprintln(os.Stderr, "FAIL: DCID mismatch")
		os.Exit(1)
	}
	if len(authOKWire) < 24+16 {
		fmt.Fprintln(os.Stderr, "auth_ok too short")
		os.Exit(1)
	}
	var okNonce [24]byte
	copy(okNonce[:], authOKWire[:24])
	okCipher := authOKWire[24:]
	okPlain, err := mistcore.UDPOpen(&kAuth, okNonce, okCipher, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "auth_ok decrypt:", err)
		os.Exit(1)
	}
	if len(okPlain) < 48 {
		fmt.Fprintln(os.Stderr, "auth_ok plain too short")
		os.Exit(1)
	}
	var srvEphPub [32]byte
	copy(srvEphPub[:], okPlain[0:32])
	var sessionID [16]byte
	copy(sessionID[:], okPlain[32:48])

	// Derive session keys.
	shared, err := mistcore.X25519Shared(&ephPriv, &srvEphPub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "shared:", err)
		os.Exit(1)
	}
	kC2S, kS2C := mistcore.DeriveSessionKeys(ephPub, srvEphPub, shared)

	session := mistcore.NewUDPSession(sessionID, kC2S, kS2C, udpAddr, codec)
	fmt.Printf("Handshake OK! Session ID: %x\n", sessionID[:8])
	fmt.Printf("Handshake time: %v\n", hsElapsed)

	// --- Wire reliability callbacks (before any data packets) ---
	// OnAckNeeded: ACK received packets immediately (untracked: ACKs are
	// never ACKed themselves).
	// OnRetransmit: resend lost frames with new packet numbers; count them.
	var dataRetransmits int
	session.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		ack := mistcore.EncodeAckFrame(0, largest, ackDelay, ranges)
		pkt, err := session.SealPacketUntracked(mistcore.DirC2S, [][]byte{ack})
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDP(pkt, udpAddr)
	}
	session.Rel.OnRetransmit = func(frames [][]byte) {
		dataRetransmits++
		pkt, err := session.SealPacket(mistcore.DirC2S, frames)
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDP(pkt, udpAddr)
	}

	// --- Data path: PING -> PONG ---
	fmt.Printf("\n--- Data path test (PING/PONG) ---\n")
	pingStart := time.Now()

	pingFrame := mistcore.EncodeUDPFrame(mistcore.UDPFramePing, 0, []byte("hello-mist-udp"))
	pkt, err := session.SealPacket(mistcore.DirC2S, [][]byte{pingFrame})
	if err != nil {
		fmt.Fprintln(os.Stderr, "seal ping:", err)
		os.Exit(1)
	}

	if _, err := conn.WriteToUDP(pkt, udpAddr); err != nil {
		fmt.Fprintln(os.Stderr, "send ping:", err)
		os.Exit(1)
	}
	fmt.Printf("Sent PING (%d bytes wire)\n", len(pkt))

	// Wait for PONG (also feeds any ACKs to the reliability layer).
	gotPong := false
	pingDeadline := time.Now().Add(5 * time.Second)
	for !gotPong && time.Now().Before(pingDeadline) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 2048)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				session.Rel.CheckRTO()
				continue
			}
			fmt.Fprintln(os.Stderr, "FAIL: PONG read:", err)
			os.Exit(1)
		}
		frames, _, err := session.OpenPacket(mistcore.DirS2C, buf[:n])
		if err != nil {
			fmt.Fprintln(os.Stderr, "open pong:", err)
			os.Exit(1)
		}
		for _, f := range frames {
			switch f.Type {
			case mistcore.UDPFramePong:
				gotPong = true
			case mistcore.UDPFrameAck:
				largest, ackDelay, ranges, derr := mistcore.DecodeAckFrame(f.Payload)
				if derr == nil {
					session.Rel.ProcessAck(largest, ackDelay, ranges)
				}
			}
		}
		session.Rel.CheckRTO()
	}
	if !gotPong {
		fmt.Fprintln(os.Stderr, "FAIL: no PONG in response")
		os.Exit(1)
	}
	pingElapsed := time.Since(pingStart)

	fmt.Printf("Got PONG! RTT: %v\n", pingElapsed)

	// --- Data echo test: SYN -> STREAM tiers -> FIN ---
	fmt.Printf("\n--- Data echo test ---\n")
	if err := runDataEcho(conn, session, udpAddr, &dataRetransmits); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL: data echo:", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== TEST PASSED ===\n")
	fmt.Printf("Handshake: %v (retransmits: %d)\n", hsElapsed, retransmits)
	fmt.Printf("PING/PONG RTT: %v\n", pingElapsed)
}

// testData returns n bytes of deterministic pseudo-random data.
func testData(n int) []byte {
	b := make([]byte, n)
	x := uint32(0x12345678)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

// echoCollector reassembles echoed STREAM data by offset.
type echoCollector struct {
	buf   []byte // reassembled bytes
	seen  []bool // per-byte seen flags (dedupe retransmit duplicates)
	got   int    // unique bytes received
	total int    // expected total
}

func (c *echoCollector) onStream(f mistcore.UDPFrame) {
	if len(f.Payload) < 8 {
		return
	}
	off := binary.BigEndian.Uint64(f.Payload[:8])
	data := f.Payload[8:]
	for i, b := range data {
		idx := int(off) + i
		if idx < 0 || idx >= len(c.buf) {
			continue
		}
		if !c.seen[idx] {
			c.seen[idx] = true
			c.got++
		}
		c.buf[idx] = b
	}
}

// pumpUntil reads datagrams until done() is true or timeout elapses.
// ACK frames are fed to the reliability layer; other frames go to onFrame.
// The RTO check runs on read timeouts and after each batch.
func pumpUntil(conn *net.UDPConn, session *mistcore.UDPSession, timeout time.Duration,
	done func() bool, onFrame func(mistcore.UDPFrame)) error {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65535)
	for {
		if done() {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("timeout waiting for peer")
		}
		d := 20 * time.Millisecond
		if d > remaining {
			d = remaining
		}
		conn.SetReadDeadline(time.Now().Add(d))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				session.Rel.CheckRTO()
				continue
			}
			return err
		}
		frames, _, err := session.OpenPacket(mistcore.DirS2C, buf[:n])
		if err != nil {
			continue // decrypt failed; ignore
		}
		for _, f := range frames {
			if f.Type == mistcore.UDPFrameAck {
				largest, ackDelay, ranges, derr := mistcore.DecodeAckFrame(f.Payload)
				if derr == nil {
					session.Rel.ProcessAck(largest, ackDelay, ranges)
				}
				continue
			}
			onFrame(f)
		}
		// Check completion BEFORE CheckRTO: the final batch's tail packets
		// may not be ACKed yet (server ACKs flush every ~10ms), and an RTO
		// check here would retransmit spuriously just before exit.
		if done() {
			return nil
		}
		session.Rel.CheckRTO()
	}
}

// runDataEcho runs the multi-tier stream echo test on a fresh stream:
// SYN, then 64B/1KB/10KB/100KB tiers with byte-exact verification,
// then FIN and waits for the peer FIN.
func runDataEcho(conn *net.UDPConn, session *mistcore.UDPSession, udpAddr *net.UDPAddr, retransmits *int) error {
	const echoSID = byte(1)
	const maxChunk = 1200 // STREAM data bytes per frame (well under MaxUDPPlaintext)

	tiers := []struct {
		label string
		size  int
	}{
		{"  64B", 64},
		{"  1KB", 1024},
		{" 10KB", 10 * 1024},
		{"100KB", 100 * 1024},
	}
	total := 0
	for _, t := range tiers {
		total += t.size
	}
	allData := testData(total)
	col := &echoCollector{buf: make([]byte, total), seen: make([]bool, total), total: total}

	send := func(frames [][]byte) error {
		for _, fr := range frames {
			pkt, err := session.SealPacket(mistcore.DirC2S, [][]byte{fr})
			if err != nil {
				return err
			}
			if _, err := conn.WriteToUDP(pkt, udpAddr); err != nil {
				return err
			}
		}
		return nil
	}

	// Open stream.
	if err := send([][]byte{mistcore.EncodeUDPFrame(mistcore.UDPFrameSyn, echoSID, nil)}); err != nil {
		return fmt.Errorf("send SYN: %w", err)
	}

	onDataFrame := func(f mistcore.UDPFrame) {
		if f.Type == mistcore.UDPFrameStream && f.SID == echoSID {
			col.onStream(f)
		}
	}

	off := 0
	for _, t := range tiers {
		baseRetrans := *retransmits
		sendStart := time.Now()
		for o := 0; o < t.size; {
			n := maxChunk
			if o+n > t.size {
				n = t.size - o
			}
			fr := mistcore.EncodeStreamFrame(echoSID, uint64(off+o), allData[off+o:off+o+n])
			if err := send([][]byte{fr}); err != nil {
				return fmt.Errorf("send STREAM: %w", err)
			}
			o += n
		}
		sendDur := time.Since(sendStart)

		recvStart := time.Now()
		want := off + t.size
		err := pumpUntil(conn, session, 30*time.Second,
			func() bool { return col.got >= want }, onDataFrame)
		if err != nil {
			return fmt.Errorf("tier %s: %w (got %d/%d bytes)", t.label, err, col.got-off, t.size)
		}
		recvDur := time.Since(recvStart)

		// Byte-exact verification of this tier's range.
		ok := true
		for i := off; i < want; i++ {
			if !col.seen[i] || col.buf[i] != allData[i] {
				ok = false
				break
			}
		}
		status := "OK"
		if !ok {
			status = "MISMATCH"
		}
		fmt.Printf("[%s] send: %v, recv: %v, retransmits: %d, %s\n",
			t.label, sendDur.Round(time.Millisecond), recvDur.Round(time.Millisecond),
			*retransmits-baseRetrans, status)
		if !ok {
			return fmt.Errorf("tier %s: echo data mismatch", t.label)
		}
		off = want
	}

	// Clean close: FIN with total stream size, wait for peer FIN.
	finPkt, err := session.SealPacket(mistcore.DirC2S,
		[][]byte{mistcore.EncodeFinFrame(echoSID, uint64(total))})
	if err != nil {
		return fmt.Errorf("seal FIN: %w", err)
	}
	if _, err := conn.WriteToUDP(finPkt, udpAddr); err != nil {
		return fmt.Errorf("send FIN: %w", err)
	}
	gotFin := false
	err = pumpUntil(conn, session, 10*time.Second,
		func() bool { return gotFin },
		func(f mistcore.UDPFrame) {
			if f.Type == mistcore.UDPFrameFin && f.SID == echoSID {
				gotFin = true
				return
			}
			onDataFrame(f)
		})
	if err != nil {
		return fmt.Errorf("wait FIN: %w", err)
	}
	fmt.Printf("Stream closed cleanly\n")
	return nil
}
