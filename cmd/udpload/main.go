package main

// Mist UDP loopback load test with simulated weak network.
//
// In-process simulated network (Go channels) with configurable one-way delay,
// per-packet loss, and token-bucket rate limiting.
//
// Measures (user's three questions):
//  1. Can BBR fill the bottleneck bandwidth?
//  2. Under high loss, does RTT sampling skew BBR's bandwidth estimate?
//  3. Does the replay sliding window falsely drop retransmitted packets?

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"mist/mistcore"
)

var (
	flagDuration = flag.Duration("duration", 30*time.Second, "test duration")
	flagPayload  = flag.Int("payload", 1200, "bytes per STREAM frame payload")
	flagRTT      = flag.Duration("rtt", 200*time.Millisecond, "simulated RTT (split equally per direction)")
	flagLoss     = flag.Float64("loss", 0.05, "per-packet loss probability per direction")
	flagRate     = flag.Float64("rate", 100.0, "simulated bottleneck rate in Mbps (0 = unlimited)")
)

// ---------------------------------------------------------------------------
// Simulated network link
// ---------------------------------------------------------------------------

type simLink struct {
	delay     time.Duration
	loss      float64
	rateBps   float64
	mu        sync.Mutex
	tokens    float64
	lastFill  time.Time
	out       chan []byte
	dropped   atomic.Int64
}

func newSimLink(oneWayDelay time.Duration, loss, rateMbps float64) *simLink {
	l := &simLink{
		delay:    oneWayDelay,
		loss:     loss,
		out:      make(chan []byte, 8192),
		lastFill: time.Now(),
	}
	if rateMbps > 0 {
		l.rateBps = rateMbps * 1e6 / 8
		l.tokens = l.rateBps
	}
	return l
}

func (l *simLink) send(data []byte) {
	if mrand.Float64() < l.loss {
		l.dropped.Add(1)
		return
	}
	if l.rateBps > 0 {
		l.mu.Lock()
		now := time.Now()
		l.tokens += now.Sub(l.lastFill).Seconds() * l.rateBps
		if l.tokens > l.rateBps {
			l.tokens = l.rateBps
		}
		l.lastFill = now
		if l.tokens < float64(len(data)) {
			l.mu.Unlock()
			l.dropped.Add(1)
			return
		}
		l.tokens -= float64(len(data))
		l.mu.Unlock()
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	d := l.delay
	go func() {
		time.Sleep(d)
		select {
		case l.out <- cp:
		default:
		}
	}()
}

// ---------------------------------------------------------------------------
// Test endpoint
// ---------------------------------------------------------------------------

type ackReq struct {
	largest  uint32
	ranges   [][2]uint32
	ackDelay time.Duration
}

type endpoint struct {
	name    string
	sess    *mistcore.UDPSession
	send    func([]byte)
	recv    chan []byte
	sendDir uint32
	recvDir uint32
	mu      sync.Mutex

	rtxCh chan [][]byte
	ackCh chan ackReq

	sentPkts   atomic.Int64
	sentBytes  atomic.Int64
	rtxPkts    atomic.Int64
	recvPkts   atomic.Int64
	ackSentCnt atomic.Int64

	sentNums     []uint32
	ackRangesLog [][][2]uint32
	recvNums     []uint32

	// sendLoop diagnostics
	cntRtx, cntAck, cntPaceWait, cntCwndBlock, cntSend int64
}

func newEndpoint(name string, sess *mistcore.UDPSession, send func([]byte), recv chan []byte, sendDir, recvDir uint32) *endpoint {
	e := &endpoint{
		name:    name,
		sess:    sess,
		send:    send,
		recv:    recv,
		sendDir: sendDir,
		recvDir: recvDir,
		rtxCh:   make(chan [][]byte, 1024),
		ackCh:   make(chan ackReq, 1024),
	}
	sess.Rel.OnRetransmit = func(frames [][]byte) {
		select {
		case e.rtxCh <- frames:
		default:
		}
	}
	sess.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		rc := make([][2]uint32, len(ranges))
		copy(rc, ranges)
		select {
		case e.ackCh <- ackReq{largest: largest, ranges: rc, ackDelay: ackDelay}:
		default:
		}
	}
	return e
}

func (e *endpoint) sendFramesTracked(frames [][]byte, isRtx bool, ctr *uint32) {
	e.mu.Lock()
	dg, err := e.sess.SealPacket(e.sendDir, frames)
	if err != nil {
		e.mu.Unlock()
		return
	}
	pn := *ctr
	*ctr++
	e.sentNums = append(e.sentNums, pn)
	e.mu.Unlock()

	e.send(dg)
	e.sentPkts.Add(1)
	e.sentBytes.Add(int64(len(dg)))
	if isRtx {
		e.rtxPkts.Add(1)
	}
}

func (e *endpoint) sendLoop(stop <-chan struct{}, wg *sync.WaitGroup, newData func() [][]byte, ctr *uint32) {
	defer wg.Done()
	defer func() {
		if e.name == "client" {
			fmt.Printf("[diag] sendLoop client: rtx=%d ack=%d paceWait=%d cwndBlock=%d sent=%d\n",
				e.cntRtx, e.cntAck, e.cntPaceWait, e.cntCwndBlock, e.cntSend)
		}
	}()
	for {
		select {
		case <-stop:
			return
		default:
		}
		select {
		case frames := <-e.rtxCh:
			e.cntRtx++
			e.sendFramesTracked(frames, true, ctr)
			continue
		default:
		}
		select {
		case aq := <-e.ackCh:
			af := mistcore.EncodeAckFrame(0, aq.largest, aq.ackDelay, aq.ranges)
			e.mu.Lock()
			e.ackRangesLog = append(e.ackRangesLog, aq.ranges)
			e.mu.Unlock()
			e.sendFramesTracked([][]byte{af}, false, ctr)
			e.ackSentCnt.Add(1)
			e.cntAck++
			continue
		default:
		}

		e.mu.Lock()
		canSend := e.sess.Rel.CanSend()
		wait := e.sess.BBR.TimeUntilSend()
		e.mu.Unlock()
		if !canSend {
			e.cntCwndBlock++
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			continue
		}
		if wait > 0 {
			e.cntPaceWait++
			select {
			case <-stop:
				return
			case <-time.After(wait):
			}
			continue
		}
		frames := newData()
		if frames == nil {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			continue
		}
		e.sendFramesTracked(frames, false, ctr)
		e.cntSend++
	}
}

func (e *endpoint) rtoLoop(stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			e.mu.Lock()
			e.sess.Rel.CheckRTO()
			e.mu.Unlock()
		}
	}
}

func (e *endpoint) recvLoop(stop <-chan struct{}, wg *sync.WaitGroup, onStream func(sid byte, offset uint64, data []byte)) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		case dg := <-e.recv:
			e.mu.Lock()
			frames, pktNum, err := e.sess.OpenPacket(e.recvDir, dg)
			if err != nil {
				e.mu.Unlock()
				continue
			}
			e.recvNums = append(e.recvNums, pktNum)
			e.mu.Unlock()
			e.recvPkts.Add(1)

			for _, f := range frames {
				switch f.Type {
				case mistcore.UDPFrameAck:
					largest, ackDelay, ranges, err := mistcore.DecodeAckFrame(f.Payload)
					if err != nil {
						continue
					}
					e.mu.Lock()
					e.sess.Rel.ProcessAck(largest, ackDelay, ranges)
					e.mu.Unlock()
				case mistcore.UDPFrameStream:
					if len(f.Payload) < 8 {
						continue
					}
					var off uint64
					for i := 0; i < 8; i++ {
						off = off<<8 | uint64(f.Payload[i])
					}
					if onStream != nil {
						onStream(f.SID, off, f.Payload[8:])
					}
				case mistcore.UDPFramePing:
					pf := mistcore.EncodeUDPFrame(mistcore.UDPFramePong, 0, nil)
					select {
					case e.rtxCh <- [][]byte{pf}:
					default:
					}
				}
			}
		}
	}
}

type bbrSample struct {
	t             time.Duration
	pacingMbps    float64
	cwndKB        float64
	inflight      int
	minRTTms      float64
	smoothedRTTms float64
	slowStart     bool
}

func (e *endpoint) sampleLoop(stop <-chan struct{}, wg *sync.WaitGroup, out *[]bbrSample, start time.Time) {
	defer wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			e.mu.Lock()
			s := bbrSample{
				t:             time.Since(start),
				pacingMbps:    e.sess.BBR.PacingRate() * 8 / 1e6,
				cwndKB:        float64(e.sess.BBR.CongestionWindow()) / 1024,
				inflight:      e.sess.Rel.BytesInFlight(),
				minRTTms:      float64(e.sess.BBR.RTTStats().MinRTT()) / 1e6,
				smoothedRTTms: float64(e.sess.BBR.RTTStats().SmoothedRTT()) / 1e6,
				slowStart:     e.sess.BBR.InSlowStart(),
			}
			e.mu.Unlock()
			*out = append(*out, s)
		}
	}
}

func main() {
	flag.Parse()
	payloadSize := *flagPayload
	duration := *flagDuration

	var sessionID [16]byte
	var keyC2S, keyS2C [32]byte
	rand.Read(sessionID[:])
	rand.Read(keyC2S[:])
	rand.Read(keyS2C[:])

	oneWay := *flagRTT / 2
	c2sLink := newSimLink(oneWay, *flagLoss, *flagRate)
	s2cLink := newSimLink(oneWay, *flagLoss, *flagRate)

	serverSess := mistcore.NewUDPSession(sessionID, keyC2S, keyS2C, nil, nil)
	clientSess := mistcore.NewUDPSession(sessionID, keyC2S, keyS2C, nil, nil)

	server := newEndpoint("server", serverSess, s2cLink.send, c2sLink.out, mistcore.DirS2C, mistcore.DirC2S)
	client := newEndpoint("client", clientSess, c2sLink.send, s2cLink.out, mistcore.DirC2S, mistcore.DirS2C)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	start := time.Now()

	var gpMu sync.Mutex
	seen := make(map[[9]byte]bool)
	var goodputBytes int64

	echoCh := make(chan []byte, 4096)

	wg.Add(1)
	go server.recvLoop(stop, &wg, func(sid byte, offset uint64, data []byte) {
		ef := mistcore.EncodeStreamFrame(sid, offset, data)
		select {
		case echoCh <- ef:
		default:
		}
	})
	var serverCtr uint32
	wg.Add(1)
	go server.sendLoop(stop, &wg, func() [][]byte {
		select {
		case ef := <-echoCh:
			return [][]byte{ef}
		default:
			return nil
		}
	}, &serverCtr)
	wg.Add(1)
	go server.rtoLoop(stop, &wg)
	var serverSamples []bbrSample
	wg.Add(1)
	go server.sampleLoop(stop, &wg, &serverSamples, start)

	var cliOffset uint64
	var cliMu sync.Mutex
	var clientCtr uint32
	wg.Add(1)
	go client.sendLoop(stop, &wg, func() [][]byte {
		cliMu.Lock()
		off := cliOffset
		cliOffset += uint64(payloadSize)
		cliMu.Unlock()
		data := make([]byte, payloadSize)
		sf := mistcore.EncodeStreamFrame(1, off, data)
		return [][]byte{sf}
	}, &clientCtr)
	wg.Add(1)
	go client.recvLoop(stop, &wg, func(sid byte, offset uint64, data []byte) {
		var key [9]byte
		key[0] = sid
		for i := 0; i < 8; i++ {
			key[8-i] = byte(offset >> (8 * i))
		}
		gpMu.Lock()
		if !seen[key] {
			seen[key] = true
			goodputBytes += int64(len(data))
		}
		gpMu.Unlock()
	})
	wg.Add(1)
	go client.rtoLoop(stop, &wg)
	var clientSamples []bbrSample
	wg.Add(1)
	go client.sampleLoop(stop, &wg, &clientSamples, start)

	time.Sleep(duration)
	close(stop)
	time.Sleep(2 * time.Second)
	wg.Wait()

	elapsed := time.Since(start).Seconds()
	gpMbps := float64(goodputBytes*8) / elapsed / 1e6

	fmt.Printf("=== Mist UDP loopback load test (simulated net) ===\n")
	fmt.Printf("duration: %.1fs  payload: %dB  rtt: %v  loss: %.1f%%  bottleneck: %.0f Mbps\n",
		elapsed, payloadSize, *flagRTT, *flagLoss*100, *flagRate)
	fmt.Printf("link drops: c2s=%d s2c=%d\n", c2sLink.dropped.Load(), s2cLink.dropped.Load())
	fmt.Printf("\n--- client (sender) ---\n")
	rtxRate := 0.0
	if client.sentPkts.Load() > 0 {
		rtxRate = 100 * float64(client.rtxPkts.Load()) / float64(client.sentPkts.Load())
	}
	fmt.Printf("sent: %d pkts / %d bytes  retransmitted: %d (%.2f%%)\n",
		client.sentPkts.Load(), client.sentBytes.Load(), client.rtxPkts.Load(), rtxRate)
	fmt.Printf("received: %d pkts  ACKs sent: %d\n", client.recvPkts.Load(), client.ackSentCnt.Load())
	fmt.Printf("GOODPUT (unique echoed bytes): %.2f Mbps\n", gpMbps)
	fmt.Printf("\n--- server (echo) ---\n")
	fmt.Printf("sent: %d pkts  retransmitted: %d  received: %d  ACKs sent: %d\n",
		server.sentPkts.Load(), server.rtxPkts.Load(), server.recvPkts.Load(), server.ackSentCnt.Load())

	fmt.Printf("\n--- client BBR (1s samples) ---\n")
	fmt.Printf("%6s %12s %10s %10s %10s %8s\n", "t", "pacing_Mbps", "cwnd_KB", "inflight", "srtt_ms", "slowstart")
	for _, s := range clientSamples {
		fmt.Printf("%6.0fs %12.2f %10.1f %10d %10.1f %8v\n",
			s.t.Seconds(), s.pacingMbps, s.cwndKB, s.inflight, s.smoothedRTTms, s.slowStart)
	}
	if len(clientSamples) > 0 {
		last := clientSamples[len(clientSamples)-1]
		fmt.Printf("final: pacing=%.2f Mbps cwnd=%.1fKB minRTT=%.1fms srtt=%.1fms\n",
			last.pacingMbps, last.cwndKB, last.minRTTms, last.smoothedRTTms)
		if *flagRate > 0 {
			fill := gpMbps / *flagRate * 100
			fmt.Printf("Q1 BBR fill: goodput %.1f / bottleneck %.0f = %.0f%% %s\n",
				gpMbps, *flagRate, fill, verdict(fill >= 80, "OK", "LOW"))
		}
		rttRatio := last.smoothedRTTms / (float64(*flagRTT) / 1e6)
		fmt.Printf("Q2 RTT sampling: smoothed %.1fms / configured %.0fms = %.2fx %s\n",
			last.smoothedRTTms, float64(*flagRTT)/1e6, rttRatio,
			verdict(rttRatio > 0.5 && rttRatio < 3.0, "OK", "SUSPECT"))
	}

	client.mu.Lock()
	server.mu.Lock()
	serverRecvSet := make(map[uint32]bool)
	for _, n := range server.recvNums {
		serverRecvSet[n] = true
	}
	sentSet := make(map[uint32]bool)
	for _, n := range client.sentNums {
		sentSet[n] = true
	}
	missing := 0
	for n := range sentSet {
		if !serverRecvSet[n] {
			missing++
		}
	}
	phantom := 0
	for n := range serverRecvSet {
		if !sentSet[n] {
			phantom++
		}
	}
	covered := make(map[uint32]bool)
	for _, ranges := range server.ackRangesLog {
		for _, r := range ranges {
			for pn := r[0]; pn <= r[1]; pn++ {
				covered[pn] = true
				if pn == math.MaxUint32 {
					break
				}
			}
		}
	}
	unacked := 0
	for n := range serverRecvSet {
		if !covered[n] {
			unacked++
		}
	}
	client.mu.Unlock()
	server.mu.Unlock()
	fmt.Printf("\n--- Q3 replay-window analysis ---\n")
	fmt.Printf("client sent %d unique C2S numbers; server decrypted %d unique; lost-in-net: %d\n",
		len(sentSet), len(serverRecvSet), missing)
	fmt.Printf("phantom (received but never sent): %d %s\n", phantom, verdict(phantom == 0, "OK", "BUG"))
	fmt.Printf("received-but-never-ACKed: %d %s\n", unacked,
		verdict(unacked == 0, "OK", "SUSPECT (Mark false-drop?)"))
	_ = serverSamples
}

func verdict(ok bool, a, b string) string {
	if ok {
		return "[" + a + "]"
	}
	return "[" + b + "]"
}
