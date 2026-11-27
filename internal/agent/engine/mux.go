package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	muxMagicByte byte = 0xA5

	muxFlagSYN  byte = 0x01
	muxFlagDATA byte = 0x02
	muxFlagACK  byte = 0x03
	muxFlagFIN  byte = 0x04
	muxFlagRST  byte = 0x05
	muxFlagPING byte = 0x06
	muxFlagPONG byte = 0x07

	muxHeaderSize          = 8 // [magic:1][flags:1][streamID:4][length:2]
	maxMuxPayload          = 32 * 1024
	initialMuxStreamWindow = 256 * 1024
	muxAckBatchThreshold   = 32 * 1024
	maxStreamsPerMuxTrunk  = 512
	maxMuxTrunksPerTarget  = 4
)

func notifyNonBlocking(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

type muxSession struct {
	conn       net.Conn
	isClient   bool
	nextID     uint32
	writeMu    sync.Mutex
	streamsMu  sync.RWMutex
	streams    map[uint32]*muxStream
	closed     int32
	closedCh   chan struct{}
	onStream   func(st *muxStream, subMode byte, clientAddr string)
	activeCnt  int32
	lastActive int64
}

func newMuxSession(conn net.Conn, isClient bool, onStream func(st *muxStream, subMode byte, clientAddr string)) *muxSession {
	startID := uint32(2)
	if isClient {
		startID = 1
	}
	s := &muxSession{
		conn:       conn,
		isClient:   isClient,
		nextID:     startID,
		streams:    make(map[uint32]*muxStream),
		closedCh:   make(chan struct{}),
		onStream:   onStream,
		lastActive: time.Now().Unix(),
	}
	go s.readLoop()
	if isClient {
		go s.keepaliveLoop()
	}
	return s
}

func (s *muxSession) IsClosed() bool {
	return atomic.LoadInt32(&s.closed) != 0
}

func (s *muxSession) ActiveStreams() int {
	return int(atomic.LoadInt32(&s.activeCnt))
}

func (s *muxSession) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}
	close(s.closedCh)
	_ = s.conn.Close()

	s.streamsMu.Lock()
	list := make([]*muxStream, 0, len(s.streams))
	for _, st := range s.streams {
		list = append(list, st)
	}
	s.streams = make(map[uint32]*muxStream)
	s.streamsMu.Unlock()

	for _, st := range list {
		st.closeLocalOnly()
	}
	return nil
}

func (s *muxSession) writeFrame(flags byte, streamID uint32, payload []byte) error {
	if s.IsClosed() {
		return net.ErrClosed
	}
	if len(payload) > maxMuxPayload {
		return fmt.Errorf("mux payload too large: %d", len(payload))
	}
	var hdr [muxHeaderSize]byte
	hdr[0] = muxMagicByte
	hdr[1] = flags
	binary.BigEndian.PutUint32(hdr[2:6], streamID)
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(payload)))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := s.conn.Write(hdr[:]); err != nil {
		_ = s.Close()
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			_ = s.Close()
			return err
		}
	}
	_ = s.conn.SetWriteDeadline(time.Time{})
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())
	return nil
}

func (s *muxSession) OpenStream(subMode byte, clientAddr string) (*muxStream, error) {
	if s.IsClosed() {
		return nil, net.ErrClosed
	}
	if s.ActiveStreams() >= maxStreamsPerMuxTrunk {
		return nil, fmt.Errorf("mux trunk saturated")
	}
	if len(clientAddr) > 128 {
		clientAddr = ""
	}
	id := atomic.AddUint32(&s.nextID, 2) - 2
	st := newMuxStream(s, id)

	s.streamsMu.Lock()
	if s.IsClosed() {
		s.streamsMu.Unlock()
		return nil, net.ErrClosed
	}
	s.streams[id] = st
	atomic.AddInt32(&s.activeCnt, 1)
	s.streamsMu.Unlock()

	synPayload := make([]byte, 2+len(clientAddr))
	synPayload[0] = subMode
	synPayload[1] = byte(len(clientAddr))
	copy(synPayload[2:], clientAddr)

	if err := s.writeFrame(muxFlagSYN, id, synPayload); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

func (s *muxSession) removeStream(id uint32) {
	s.streamsMu.Lock()
	_, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
		atomic.AddInt32(&s.activeCnt, -1)
	}
	s.streamsMu.Unlock()
}

func (s *muxSession) keepaliveLoop() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closedCh:
			return
		case <-ticker.C:
			if s.IsClosed() {
				return
			}
			// Evict completely idle trunks after 90s so idle sockets don't linger forever
			if s.ActiveStreams() == 0 && time.Now().Unix()-atomic.LoadInt64(&s.lastActive) > 90 {
				_ = s.Close()
				return
			}
			_ = s.writeFrame(muxFlagPING, 0, nil)
		}
	}
}

func (s *muxSession) readLoop() {
	defer s.Close()
	var hdr [muxHeaderSize]byte
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return
		}
		if hdr[0] != muxMagicByte {
			return
		}
		flags := hdr[1]
		streamID := binary.BigEndian.Uint32(hdr[2:6])
		length := int(binary.BigEndian.Uint16(hdr[6:8]))
		if length > maxMuxPayload {
			return
		}
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			_ = s.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				return
			}
		}
		_ = s.conn.SetReadDeadline(time.Time{})
		atomic.StoreInt64(&s.lastActive, time.Now().Unix())

		switch flags {
		case muxFlagPING:
			_ = s.writeFrame(muxFlagPONG, 0, nil)
		case muxFlagPONG:
		case muxFlagSYN:
			if s.isClient || s.onStream == nil || len(payload) < 2 {
				continue
			}
			if s.ActiveStreams() >= maxStreamsPerMuxTrunk {
				_ = s.writeFrame(muxFlagRST, streamID, nil)
				continue
			}
			subMode := payload[0]
			addrLen := int(payload[1])
			if 2+addrLen > len(payload) || addrLen > 128 {
				_ = s.writeFrame(muxFlagRST, streamID, nil)
				continue
			}
			clientAddr := string(payload[2 : 2+addrLen])
			if clientAddr != "" {
				if h, p, sErr := net.SplitHostPort(clientAddr); sErr != nil || net.ParseIP(h) == nil || len(p) == 0 {
					clientAddr = ""
				}
			}
			st := newMuxStream(s, streamID)
			s.streamsMu.Lock()
			if _, exists := s.streams[streamID]; exists || s.IsClosed() {
				s.streamsMu.Unlock()
				_ = s.writeFrame(muxFlagRST, streamID, nil)
				continue
			}
			s.streams[streamID] = st
			atomic.AddInt32(&s.activeCnt, 1)
			s.streamsMu.Unlock()
			go s.onStream(st, subMode, clientAddr)

		case muxFlagDATA:
			st := s.getStream(streamID)
			if st == nil {
				_ = s.writeFrame(muxFlagRST, streamID, nil)
				continue
			}
			if !st.pushData(payload) {
				_ = st.Close()
			}

		case muxFlagACK:
			if len(payload) != 4 {
				continue
			}
			delta := binary.BigEndian.Uint32(payload)
			if st := s.getStream(streamID); st != nil {
				st.addSendWindow(int64(delta))
			}

		case muxFlagFIN:
			if st := s.getStream(streamID); st != nil {
				st.markRemoteFIN()
			}

		case muxFlagRST:
			if st := s.getStream(streamID); st != nil {
				st.markRemoteRST()
				s.removeStream(streamID)
			}
		}
	}
}

func (s *muxSession) getStream(id uint32) *muxStream {
	s.streamsMu.RLock()
	st := s.streams[id]
	s.streamsMu.RUnlock()
	return st
}

type muxStream struct {
	sess *muxSession
	id   uint32

	recvMu       sync.Mutex
	recvBuf      bytes.Buffer
	unackedBytes int
	remoteFIN    bool
	remoteRST    bool
	recvWake     chan struct{}

	sendMu    sync.Mutex
	sendWin   int64
	localFIN  bool
	sendWake  chan struct{}

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	closed   int32
	closedCh chan struct{}
}

func newMuxStream(sess *muxSession, id uint32) *muxStream {
	return &muxStream{
		sess:     sess,
		id:       id,
		sendWin:  initialMuxStreamWindow,
		recvWake: make(chan struct{}, 1),
		sendWake: make(chan struct{}, 1),
		closedCh: make(chan struct{}),
	}
}

func (st *muxStream) pushData(p []byte) bool {
	if len(p) == 0 {
		return true
	}
	st.recvMu.Lock()
	if st.remoteFIN || st.remoteRST || atomic.LoadInt32(&st.closed) != 0 {
		st.recvMu.Unlock()
		return false
	}
	if st.recvBuf.Len()+len(p) > initialMuxStreamWindow*2 {
		st.recvMu.Unlock()
		return false
	}
	_, _ = st.recvBuf.Write(p)
	st.recvMu.Unlock()
	notifyNonBlocking(st.recvWake)
	return true
}

func (st *muxStream) addSendWindow(delta int64) {
	if delta <= 0 {
		return
	}
	st.sendMu.Lock()
	if st.sendWin+delta <= initialMuxStreamWindow*2 {
		st.sendWin += delta
	}
	st.sendMu.Unlock()
	notifyNonBlocking(st.sendWake)
}

func (st *muxStream) markRemoteFIN() {
	st.recvMu.Lock()
	st.remoteFIN = true
	st.recvMu.Unlock()
	notifyNonBlocking(st.recvWake)
}

func (st *muxStream) markRemoteRST() {
	st.recvMu.Lock()
	st.remoteRST = true
	st.recvMu.Unlock()
	st.closeLocalOnly()
}

func (st *muxStream) closeLocalOnly() {
	if atomic.CompareAndSwapInt32(&st.closed, 0, 1) {
		close(st.closedCh)
		notifyNonBlocking(st.recvWake)
		notifyNonBlocking(st.sendWake)
	}
}

func (st *muxStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		st.recvMu.Lock()
		if st.recvBuf.Len() > 0 {
			n, _ := st.recvBuf.Read(p)
			st.unackedBytes += n
			ack := 0
			if st.unackedBytes >= muxAckBatchThreshold || (st.recvBuf.Len() == 0 && st.unackedBytes > 0) {
				ack = st.unackedBytes
				st.unackedBytes = 0
			}
			st.recvMu.Unlock()
			if ack > 0 && atomic.LoadInt32(&st.closed) == 0 {
				var ackBuf [4]byte
				binary.BigEndian.PutUint32(ackBuf[:], uint32(ack))
				_ = st.sess.writeFrame(muxFlagACK, st.id, ackBuf[:])
			}
			return n, nil
		}
		if st.remoteRST {
			st.recvMu.Unlock()
			return 0, io.EOF
		}
		if st.remoteFIN {
			st.recvMu.Unlock()
			return 0, io.EOF
		}
		if atomic.LoadInt32(&st.closed) != 0 || st.sess.IsClosed() {
			st.recvMu.Unlock()
			return 0, net.ErrClosed
		}
		st.recvMu.Unlock()

		var timerCh <-chan time.Time
		var timer *time.Timer
		st.deadlineMu.Lock()
		dl := st.readDeadline
		st.deadlineMu.Unlock()
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, errMuxDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timerCh = timer.C
		}

		select {
		case <-st.recvWake:
		case <-st.closedCh:
		case <-st.sess.closedCh:
		case <-timerCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, errMuxDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// timeoutNetErr satisfies net.Error with Timeout() == true so UDP read loops handle mux deadlines identically to sockets.
type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }

var errMuxDeadlineExceeded error = timeoutNetErr{}

func (st *muxStream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.sendMu.Lock()
		if st.localFIN || atomic.LoadInt32(&st.closed) != 0 || st.sess.IsClosed() {
			st.sendMu.Unlock()
			return total, net.ErrClosed
		}
		avail := st.sendWin
		if avail <= 0 {
			st.sendMu.Unlock()

			var timerCh <-chan time.Time
			var timer *time.Timer
			st.deadlineMu.Lock()
			dl := st.writeDeadline
			st.deadlineMu.Unlock()
			if !dl.IsZero() {
				d := time.Until(dl)
				if d <= 0 {
					return total, errMuxDeadlineExceeded
				}
				timer = time.NewTimer(d)
				timerCh = timer.C
			}
			select {
			case <-st.sendWake:
			case <-st.closedCh:
			case <-st.sess.closedCh:
			case <-timerCh:
				if timer != nil {
					timer.Stop()
				}
				return total, errMuxDeadlineExceeded
			}
			if timer != nil {
				timer.Stop()
			}
			continue
		}

		chunk := len(p)
		if int64(chunk) > avail {
			chunk = int(avail)
		}
		if chunk > maxMuxPayload {
			chunk = maxMuxPayload
		}
		st.sendWin -= int64(chunk)
		st.sendMu.Unlock()

		if err := st.sess.writeFrame(muxFlagDATA, st.id, p[:chunk]); err != nil {
			return total, err
		}
		total += chunk
		p = p[chunk:]
	}
	return total, nil
}

func (st *muxStream) CloseWrite() error {
	st.sendMu.Lock()
	if st.localFIN {
		st.sendMu.Unlock()
		return nil
	}
	st.localFIN = true
	st.sendMu.Unlock()
	notifyNonBlocking(st.sendWake)
	return st.sess.writeFrame(muxFlagFIN, st.id, nil)
}

func (st *muxStream) Close() error {
	if !atomic.CompareAndSwapInt32(&st.closed, 0, 1) {
		return nil
	}
	close(st.closedCh)
	notifyNonBlocking(st.recvWake)
	notifyNonBlocking(st.sendWake)
	st.sess.removeStream(st.id)
	_ = st.sess.writeFrame(muxFlagRST, st.id, nil)
	return nil
}

func (st *muxStream) LocalAddr() net.Addr  { return st.sess.conn.LocalAddr() }
func (st *muxStream) RemoteAddr() net.Addr { return st.sess.conn.RemoteAddr() }

func (st *muxStream) SetDeadline(t time.Time) error {
	st.deadlineMu.Lock()
	st.readDeadline = t
	st.writeDeadline = t
	st.deadlineMu.Unlock()
	notifyNonBlocking(st.recvWake)
	notifyNonBlocking(st.sendWake)
	return nil
}

func (st *muxStream) SetReadDeadline(t time.Time) error {
	st.deadlineMu.Lock()
	st.readDeadline = t
	st.deadlineMu.Unlock()
	notifyNonBlocking(st.recvWake)
	return nil
}

func (st *muxStream) SetWriteDeadline(t time.Time) error {
	st.deadlineMu.Lock()
	st.writeDeadline = t
	st.deadlineMu.Unlock()
	notifyNonBlocking(st.sendWake)
	return nil
}

// muxClientPool maintains reusable authenticated muxSession trunks per upstream target index.
type muxClientPool struct {
	mu     sync.Mutex
	dialMu sync.Mutex
	closed bool
	trunks map[int][]*muxSession
	rr     uint64
}

func newMuxClientPool() *muxClientPool {
	return &muxClientPool{
		trunks: make(map[int][]*muxSession),
	}
}

func (p *muxClientPool) pickTrunkLocked(targetIdx int, allowBusy bool) *muxSession {
	alive := p.trunks[targetIdx][:0]
	for _, tr := range p.trunks[targetIdx] {
		if !tr.IsClosed() {
			alive = append(alive, tr)
		}
	}
	p.trunks[targetIdx] = alive
	if len(alive) == 0 {
		return nil
	}
	start := int(atomic.AddUint64(&p.rr, 1)-1) % len(alive)
	for i := 0; i < len(alive); i++ {
		cand := alive[(start+i)%len(alive)]
		if cand.ActiveStreams() < maxStreamsPerMuxTrunk {
			if !allowBusy && cand.ActiveStreams() >= 16 && len(alive) < maxMuxTrunksPerTarget {
				return nil
			}
			return cand
		}
	}
	return nil
}

func (p *muxClientPool) OpenStream(
	ctx context.Context,
	targetIdx int,
	subMode byte,
	clientAddr string,
	dialTrunk func(ctx context.Context) (net.Conn, error),
) (net.Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	chosen := p.pickTrunkLocked(targetIdx, false)
	p.mu.Unlock()

	if chosen != nil {
		if st, err := chosen.OpenStream(subMode, clientAddr); err == nil {
			return st, nil
		}
	}

	p.dialMu.Lock()
	defer p.dialMu.Unlock()

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	allowBusy := len(p.trunks[targetIdx]) >= maxMuxTrunksPerTarget
	chosen = p.pickTrunkLocked(targetIdx, allowBusy)
	p.mu.Unlock()

	if chosen != nil {
		if st, err := chosen.OpenStream(subMode, clientAddr); err == nil {
			return st, nil
		}
	}

	rawTrunk, err := dialTrunk(ctx)
	if err != nil {
		return nil, err
	}
	sess := newMuxSession(rawTrunk, true, nil)

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = sess.Close()
		return nil, net.ErrClosed
	}
	p.trunks[targetIdx] = append(p.trunks[targetIdx], sess)
	p.mu.Unlock()

	st, err := sess.OpenStream(subMode, clientAddr)
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	return st, nil
}

func (p *muxClientPool) CloseAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	var all []*muxSession
	for k, list := range p.trunks {
		all = append(all, list...)
		delete(p.trunks, k)
	}
	p.mu.Unlock()
	for _, s := range all {
		_ = s.Close()
	}
}

var _ = errors.New
