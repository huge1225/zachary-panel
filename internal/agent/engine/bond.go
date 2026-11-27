package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bondFlagData byte = 0x01
	bondFlagFIN  byte = 0x02
	bondFlagRST  byte = 0x03

	bondChunkHeaderSize = 11 // [flags:1][seq:8][length:2]
	maxBondChunkPayload = 16 * 1024
	maxBondReorderAhead = 64 // Max 64 * 16 KiB = 1 MiB reorder buffer per bonded connection
	maxPendingBonds     = 256
)

type bondOutFrame struct {
	flags   byte
	seq     uint64
	payload []byte
}

type bondLink struct {
	conn  net.Conn
	outCh chan bondOutFrame
}

// bondedConn aggregates M parallel authenticated tunnel links into a single ordered, full-duplex net.Conn
// by striping 16 KiB chunks across all member links concurrently and reassembling by sequence number.
type bondedConn struct {
	links      []*bondLink
	writeCallM sync.Mutex
	writeSeq   uint64
	localFIN   bool

	recvMu       sync.Mutex
	spaceCond    *sync.Cond
	nextReadSeq  uint64
	reorder      map[uint64][]byte
	curChunk     bytes.Buffer
	finReceived  bool
	finSeq       uint64
	remoteRST    bool
	recvWake     chan struct{}

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	closed        int32
	activeReaders int32
	closedCh      chan struct{}
	writerWG      sync.WaitGroup
	wg            sync.WaitGroup
}

func newBondedConn(conns []net.Conn) *bondedConn {
	bc := &bondedConn{
		links:         make([]*bondLink, len(conns)),
		reorder:       make(map[uint64][]byte),
		recvWake:      make(chan struct{}, 1),
		closedCh:      make(chan struct{}),
		activeReaders: int32(len(conns)),
	}
	bc.spaceCond = sync.NewCond(&bc.recvMu)
	for i, c := range conns {
		bl := &bondLink{
			conn:  c,
			outCh: make(chan bondOutFrame, 16),
		}
		bc.links[i] = bl
		bc.writerWG.Add(1)
		bc.wg.Add(2)
		go bc.linkWriter(bl)
		go bc.linkReader(c)
	}
	return bc
}

func (bc *bondedConn) linkWriter(bl *bondLink) {
	defer bc.wg.Done()
	defer bc.writerWG.Done()
	var hdr [bondChunkHeaderSize]byte
	for {
		select {
		case <-bc.closedCh:
			return
		case fr, ok := <-bl.outCh:
			if !ok {
				closeWrite(bl.conn)
				return
			}
			hdr[0] = fr.flags
			binary.BigEndian.PutUint64(hdr[1:9], fr.seq)
			binary.BigEndian.PutUint16(hdr[9:11], uint16(len(fr.payload)))
			_ = bl.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if _, err := bl.conn.Write(hdr[:]); err != nil {
				bc.markBroken()
				return
			}
			if len(fr.payload) > 0 {
				if _, err := bl.conn.Write(fr.payload); err != nil {
					bc.markBroken()
					return
				}
			}
			_ = bl.conn.SetWriteDeadline(time.Time{})
		}
	}
}

func (bc *bondedConn) linkReader(c net.Conn) {
	defer bc.wg.Done()
	defer func() {
		if atomic.AddInt32(&bc.activeReaders, -1) == 0 {
			bc.recvMu.Lock()
			bc.remoteRST = true
			bc.spaceCond.Broadcast()
			bc.recvMu.Unlock()
			notifyNonBlocking(bc.recvWake)
		}
	}()
	var hdr [bondChunkHeaderSize]byte
	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			// Every clean link must send bondFlagFIN before closing; raw EOF before bondFlagFIN is a truncated member link.
			bc.markBrokenIfUnfinished()
			return
		}
		flags := hdr[0]
		seq := binary.BigEndian.Uint64(hdr[1:9])
		length := int(binary.BigEndian.Uint16(hdr[9:11]))
		if length > maxBondChunkPayload {
			bc.markBroken()
			return
		}
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(c, payload); err != nil {
				bc.markBrokenIfUnfinished()
				return
			}
		}

		switch flags {
		case bondFlagData:
			bc.recvMu.Lock()
			for !bc.remoteRST && atomic.LoadInt32(&bc.closed) == 0 && seq >= bc.nextReadSeq && seq-bc.nextReadSeq >= maxBondReorderAhead {
				bc.spaceCond.Wait()
			}
			if bc.remoteRST || atomic.LoadInt32(&bc.closed) != 0 {
				bc.recvMu.Unlock()
				return
			}
			if seq >= bc.nextReadSeq {
				bc.reorder[seq] = payload
				bc.recvMu.Unlock()
				notifyNonBlocking(bc.recvWake)
			} else {
				bc.recvMu.Unlock()
			}
		case bondFlagFIN:
			bc.recvMu.Lock()
			bc.finReceived = true
			bc.finSeq = seq
			bc.recvMu.Unlock()
			notifyNonBlocking(bc.recvWake)
			return
		case bondFlagRST:
			bc.markBroken()
			return
		default:
			bc.markBroken()
			return
		}
	}
}

func (bc *bondedConn) markBrokenIfUnfinished() {
	bc.recvMu.Lock()
	done := bc.finReceived && bc.nextReadSeq >= bc.finSeq
	if !done {
		bc.remoteRST = true
		bc.spaceCond.Broadcast()
	}
	bc.recvMu.Unlock()
	notifyNonBlocking(bc.recvWake)
}

func (bc *bondedConn) markBroken() {
	bc.recvMu.Lock()
	bc.remoteRST = true
	bc.spaceCond.Broadcast()
	bc.recvMu.Unlock()
	notifyNonBlocking(bc.recvWake)
	_ = bc.Close()
}

func (bc *bondedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		bc.recvMu.Lock()
		if bc.curChunk.Len() == 0 {
			advanced := false
			for {
				chunk, ok := bc.reorder[bc.nextReadSeq]
				if !ok {
					break
				}
				delete(bc.reorder, bc.nextReadSeq)
				bc.nextReadSeq++
				advanced = true
				_, _ = bc.curChunk.Write(chunk)
				if bc.curChunk.Len() >= len(p) {
					break
				}
			}
			if advanced {
				bc.spaceCond.Broadcast()
			}
		}
		if bc.curChunk.Len() > 0 {
			n, _ := bc.curChunk.Read(p)
			bc.recvMu.Unlock()
			return n, nil
		}
		if bc.finReceived && bc.nextReadSeq >= bc.finSeq {
			bc.recvMu.Unlock()
			return 0, io.EOF
		}
		if bc.remoteRST {
			bc.recvMu.Unlock()
			return 0, io.EOF
		}
		if atomic.LoadInt32(&bc.closed) != 0 {
			bc.recvMu.Unlock()
			return 0, net.ErrClosed
		}
		bc.recvMu.Unlock()

		var timerCh <-chan time.Time
		var timer *time.Timer
		bc.deadlineMu.Lock()
		dl := bc.readDeadline
		bc.deadlineMu.Unlock()
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, timeoutNetErr{}
			}
			timer = time.NewTimer(d)
			timerCh = timer.C
		}

		select {
		case <-bc.recvWake:
		case <-bc.closedCh:
		case <-timerCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, timeoutNetErr{}
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (bc *bondedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	bc.writeCallM.Lock()
	defer bc.writeCallM.Unlock()

	if bc.localFIN || atomic.LoadInt32(&bc.closed) != 0 {
		return 0, net.ErrClosed
	}

	total := 0
	m := uint64(len(bc.links))
	for len(p) > 0 {
		chunkLen := len(p)
		if chunkLen > maxBondChunkPayload {
			chunkLen = maxBondChunkPayload
		}
		buf := make([]byte, chunkLen)
		copy(buf, p[:chunkLen])
		seq := bc.writeSeq
		bc.writeSeq++
		link := bc.links[seq%m]

		var timerCh <-chan time.Time
		var timer *time.Timer
		bc.deadlineMu.Lock()
		dl := bc.writeDeadline
		bc.deadlineMu.Unlock()
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return total, timeoutNetErr{}
			}
			timer = time.NewTimer(d)
			timerCh = timer.C
		}

		select {
		case link.outCh <- bondOutFrame{flags: bondFlagData, seq: seq, payload: buf}:
		case <-bc.closedCh:
			if timer != nil {
				timer.Stop()
			}
			return total, net.ErrClosed
		case <-timerCh:
			if timer != nil {
				timer.Stop()
			}
			return total, timeoutNetErr{}
		}
		if timer != nil {
			timer.Stop()
		}

		total += chunkLen
		p = p[chunkLen:]
	}
	return total, nil
}

func (bc *bondedConn) CloseWrite() error {
	bc.writeCallM.Lock()
	if bc.localFIN || atomic.LoadInt32(&bc.closed) != 0 {
		bc.writeCallM.Unlock()
		return nil
	}
	bc.localFIN = true
	finSeq := bc.writeSeq
	for _, l := range bc.links {
		select {
		case l.outCh <- bondOutFrame{flags: bondFlagFIN, seq: finSeq}:
		case <-bc.closedCh:
			bc.writeCallM.Unlock()
			return nil
		}
		close(l.outCh)
	}
	bc.writeCallM.Unlock()

	bc.writerWG.Wait()
	return nil
}

func (bc *bondedConn) Close() error {
	if !atomic.CompareAndSwapInt32(&bc.closed, 0, 1) {
		return nil
	}
	close(bc.closedCh)
	for _, l := range bc.links {
		_ = l.conn.Close()
	}
	bc.recvMu.Lock()
	bc.spaceCond.Broadcast()
	bc.recvMu.Unlock()
	notifyNonBlocking(bc.recvWake)
	return nil
}

func (bc *bondedConn) LocalAddr() net.Addr  { return bc.links[0].conn.LocalAddr() }
func (bc *bondedConn) RemoteAddr() net.Addr { return bc.links[0].conn.RemoteAddr() }

func (bc *bondedConn) SetDeadline(t time.Time) error {
	bc.deadlineMu.Lock()
	bc.readDeadline = t
	bc.writeDeadline = t
	bc.deadlineMu.Unlock()
	notifyNonBlocking(bc.recvWake)
	return nil
}

func (bc *bondedConn) SetReadDeadline(t time.Time) error {
	bc.deadlineMu.Lock()
	bc.readDeadline = t
	bc.deadlineMu.Unlock()
	notifyNonBlocking(bc.recvWake)
	return nil
}

func (bc *bondedConn) SetWriteDeadline(t time.Time) error {
	bc.deadlineMu.Lock()
	bc.writeDeadline = t
	bc.deadlineMu.Unlock()
	return nil
}

// --- Bond Handshake & Server Reassembly Hub ---

type pendingBondGroup struct {
	totalLinks int
	subMode    byte
	clientAddr string
	conns      []net.Conn
	seenIdx    map[int]bool
	createdAt  time.Time
}

type bondServerHub struct {
	mu      sync.Mutex
	pending map[[16]byte]*pendingBondGroup
	lastGC  time.Time
}

func newBondServerHub() *bondServerHub {
	return &bondServerHub{
		pending: make(map[[16]byte]*pendingBondGroup),
		lastGC:  time.Now(),
	}
}

func (h *bondServerHub) CloseAll() {
	if h == nil {
		return
	}
	h.mu.Lock()
	groups := make([]*pendingBondGroup, 0, len(h.pending))
	for id, g := range h.pending {
		groups = append(groups, g)
		delete(h.pending, id)
	}
	h.mu.Unlock()
	for _, g := range groups {
		for _, c := range g.conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}
}

func (h *bondServerHub) gcLocked(now time.Time) {
	if now.Sub(h.lastGC) < 2*time.Second && len(h.pending) < maxPendingBonds {
		return
	}
	for id, g := range h.pending {
		if now.Sub(g.createdAt) > 6*time.Second {
			for _, c := range g.conns {
				if c != nil {
					_ = c.Close()
				}
			}
			delete(h.pending, id)
		}
	}
	h.lastGC = now
}

// AcceptMember reads the post-auth bond member header from conn. When the final member link of the group arrives,
// it sends the 1-byte ready ACK on all member links and returns (assembledBondedConn, subMode, clientAddr, true, nil).
// Non-final member links return (nil, 0, "", false, nil) and their goroutine MUST NOT close conn on return!
func (h *bondServerHub) AcceptMember(conn net.Conn) (*bondedConn, byte, string, bool, error) {
	var fixed [20]byte // [bondID:16][linkIdx:1][totalLinks:1][subMode:1][addrLen:1]
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, fixed[:]); err != nil {
		_ = conn.SetReadDeadline(time.Time{})
		return nil, 0, "", false, err
	}
	var bondID [16]byte
	copy(bondID[:], fixed[0:16])
	linkIdx := int(fixed[16])
	totalLinks := int(fixed[17])
	subMode := fixed[18]
	addrLen := int(fixed[19])
	if totalLinks < 1 || totalLinks > 8 || linkIdx < 0 || linkIdx >= totalLinks || addrLen > 128 {
		_ = conn.SetReadDeadline(time.Time{})
		return nil, 0, "", false, fmt.Errorf("invalid bond header parameters (idx=%d total=%d)", linkIdx, totalLinks)
	}
	var clientAddr string
	if addrLen > 0 {
		raw := make([]byte, addrLen)
		if _, err := io.ReadFull(conn, raw); err != nil {
			_ = conn.SetReadDeadline(time.Time{})
			return nil, 0, "", false, err
		}
		clientAddr = string(raw)
		if host, port, sErr := net.SplitHostPort(clientAddr); sErr != nil || net.ParseIP(host) == nil || len(port) == 0 {
			clientAddr = ""
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	if totalLinks == 1 {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte{0x01}); err != nil {
			return nil, 0, "", false, err
		}
		_ = conn.SetWriteDeadline(time.Time{})
		return newBondedConn([]net.Conn{conn}), subMode, clientAddr, true, nil
	}

	now := time.Now()
	h.mu.Lock()
	h.gcLocked(now)
	grp, exists := h.pending[bondID]
	if !exists {
		if len(h.pending) >= maxPendingBonds {
			h.mu.Unlock()
			return nil, 0, "", false, fmt.Errorf("bond server pending queue full")
		}
		grp = &pendingBondGroup{
			totalLinks: totalLinks,
			subMode:    subMode,
			clientAddr: clientAddr,
			conns:      make([]net.Conn, totalLinks),
			seenIdx:    make(map[int]bool, totalLinks),
			createdAt:  now,
		}
		h.pending[bondID] = grp
	}
	if grp.totalLinks != totalLinks || grp.seenIdx[linkIdx] {
		h.mu.Unlock()
		return nil, 0, "", false, fmt.Errorf("duplicate or mismatched bond link index")
	}
	grp.conns[linkIdx] = conn
	grp.seenIdx[linkIdx] = true
	ready := len(grp.seenIdx) == grp.totalLinks
	if ready {
		delete(h.pending, bondID)
	}
	h.mu.Unlock()

	if !ready {
		return nil, 0, "", false, nil
	}

	for _, c := range grp.conns {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte{0x01}); err != nil {
			for _, oc := range grp.conns {
				_ = oc.Close()
			}
			return nil, 0, "", false, err
		}
		_ = c.SetWriteDeadline(time.Time{})
	}
	return newBondedConn(grp.conns), grp.subMode, grp.clientAddr, true, nil
}

// dialBondedStream establishes up to numLinks parallel authenticated TunnelModeBond connections using dialMember
// and returns a single chunk-striped *bondedConn.
func dialBondedStream(
	ctx context.Context,
	numLinks int,
	subMode byte,
	clientAddr string,
	dialMember func(ctx context.Context, slot int) (net.Conn, error),
) (net.Conn, error) {
	if numLinks < 2 {
		numLinks = 2
	}
	if numLinks > 8 {
		numLinks = 8
	}
	if len(clientAddr) > 128 {
		clientAddr = ""
	}

	type resItem struct {
		slot int
		conn net.Conn
		err  error
	}
	resCh := make(chan resItem, numLinks)
	for i := 0; i < numLinks; i++ {
		go func(slot int) {
			c, err := dialMember(ctx, slot)
			resCh <- resItem{slot: slot, conn: c, err: err}
		}(i)
	}

	var conns []net.Conn
	var lastErr error
	for i := 0; i < numLinks; i++ {
		r := <-resCh
		if r.err != nil {
			lastErr = r.err
			continue
		}
		conns = append(conns, r.conn)
	}
	if len(conns) == 0 {
		return nil, fmt.Errorf("bonded dial failed on all %d links: %w", numLinks, lastErr)
	}

	var bondID [16]byte
	if _, err := rand.Read(bondID[:]); err != nil {
		for _, c := range conns {
			_ = c.Close()
		}
		return nil, err
	}

	total := len(conns)
	errCh := make(chan error, total)
	for idx, c := range conns {
		go func(linkIdx int, conn net.Conn) {
			hdr := make([]byte, 20+len(clientAddr))
			copy(hdr[0:16], bondID[:])
			hdr[16] = byte(linkIdx)
			hdr[17] = byte(total)
			hdr[18] = subMode
			hdr[19] = byte(len(clientAddr))
			copy(hdr[20:], clientAddr)

			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, wErr := conn.Write(hdr); wErr != nil {
				errCh <- wErr
				return
			}
			_ = conn.SetWriteDeadline(time.Time{})

			var ack [1]byte
			_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
			_, rErr := io.ReadFull(conn, ack[:])
			_ = conn.SetReadDeadline(time.Time{})
			if rErr != nil {
				errCh <- rErr
				return
			}
			if ack[0] != 0x01 {
				errCh <- fmt.Errorf("unexpected bond ready byte 0x%x", ack[0])
				return
			}
			errCh <- nil
		}(idx, c)
	}

	for i := 0; i < total; i++ {
		if hErr := <-errCh; hErr != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("bond handshake failed: %w", hErr)
		}
	}
	return newBondedConn(conns), nil
}
