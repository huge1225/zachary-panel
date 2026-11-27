package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"nexus-panel/internal/agent/security"
)

const maxSNIPeekBytes = 8192

// peekedConn replays already-inspected initial bytes before reading from the underlying net.Conn.
type peekedConn struct {
	net.Conn
	buf []byte
}

func (p *peekedConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *peekedConn) CloseWrite() error {
	closeWrite(p.Conn)
	return nil
}

// ExtractSNIOrHost peeks up to 8 KiB from conn within timeout to extract a TLS ClientHello ServerName (SNI)
// or an HTTP Host header without decrypting TLS, returning the normalized lowercase hostname and a replayed net.Conn.
func ExtractSNIOrHost(conn net.Conn, timeout time.Duration) (string, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)

	readMore := func() error {
		if len(buf) >= maxSNIPeekBytes {
			return fmt.Errorf("SNI/Host header exceeds %d bytes", maxSNIPeekBytes)
		}
		limit := maxSNIPeekBytes - len(buf)
		if limit > len(tmp) {
			limit = len(tmp)
		}
		n, err := conn.Read(tmp[:limit])
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil && n == 0 {
			return err
		}
		return nil
	}

	if err := readMore(); err != nil {
		return "", &peekedConn{Conn: conn, buf: buf}, err
	}

	// Case 1: TLS Handshake record (ContentType == 0x16)
	if len(buf) > 0 && buf[0] == 0x16 {
		for {
			sni, needMore, err := tryParseTLSClientHelloSNI(buf)
			if err != nil {
				return "", &peekedConn{Conn: conn, buf: buf}, err
			}
			if !needMore {
				return normalizeRoutedHost(sni), &peekedConn{Conn: conn, buf: buf}, nil
			}
			if rErr := readMore(); rErr != nil {
				return "", &peekedConn{Conn: conn, buf: buf}, rErr
			}
		}
	}

	// Case 2: HTTP/1.x Host header
	for {
		endIdx := bytes.Index(buf, []byte("\r\n\r\n"))
		if endIdx >= 0 {
			host := parseHTTPHostHeader(buf[:endIdx+2])
			return normalizeRoutedHost(host), &peekedConn{Conn: conn, buf: buf}, nil
		}
		if len(buf) >= maxSNIPeekBytes {
			return "", &peekedConn{Conn: conn, buf: buf}, fmt.Errorf("HTTP headers exceed %d bytes", maxSNIPeekBytes)
		}
		if rErr := readMore(); rErr != nil {
			// Check if Host header already appeared before EOF
			if host := parseHTTPHostHeader(buf); host != "" {
				return normalizeRoutedHost(host), &peekedConn{Conn: conn, buf: buf}, nil
			}
			return "", &peekedConn{Conn: conn, buf: buf}, rErr
		}
	}
}

func normalizeRoutedHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	return s
}

func parseHTTPHostHeader(hdrBytes []byte) string {
	lines := bytes.Split(hdrBytes, []byte("\r\n"))
	if len(lines) == 0 {
		return ""
	}
	// Verify first line resembles an HTTP request line
	first := string(lines[0])
	if !strings.Contains(first, " HTTP/1.") {
		return ""
	}
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if len(line) >= 5 && strings.EqualFold(string(line[:5]), "host:") {
			return strings.TrimSpace(string(line[5:]))
		}
	}
	return ""
}

// tryParseTLSClientHelloSNI reassembles TLS handshake records from buf and extracts the SNI host_name.
// Returns (sni, needMoreBytes, err).
func tryParseTLSClientHelloSNI(buf []byte) (string, bool, error) {
	var hsPayload []byte
	offset := 0
	for offset < len(buf) {
		if len(buf)-offset < 5 {
			if len(hsPayload) >= 4 {
				hsLen := int(hsPayload[1])<<16 | int(hsPayload[2])<<8 | int(hsPayload[3])
				if len(hsPayload) >= 4+hsLen {
					break
				}
			}
			return "", true, nil
		}
		if buf[offset] != 0x16 {
			return "", false, fmt.Errorf("unexpected TLS record type 0x%x", buf[offset])
		}
		recLen := int(binary.BigEndian.Uint16(buf[offset+3 : offset+5]))
		if recLen > 16384 {
			return "", false, fmt.Errorf("oversized TLS record (%d)", recLen)
		}
		if len(buf)-offset < 5+recLen {
			return "", true, nil
		}
		hsPayload = append(hsPayload, buf[offset+5:offset+5+recLen]...)
		offset += 5 + recLen
		if len(hsPayload) >= 4 {
			hsLen := int(hsPayload[1])<<16 | int(hsPayload[2])<<8 | int(hsPayload[3])
			if len(hsPayload) >= 4+hsLen {
				break
			}
		}
	}

	if len(hsPayload) < 4 {
		return "", true, nil
	}
	if hsPayload[0] != 0x01 { // HandshakeType ClientHello == 1
		return "", false, fmt.Errorf("not a TLS ClientHello (type=%d)", hsPayload[0])
	}
	hsLen := int(hsPayload[1])<<16 | int(hsPayload[2])<<8 | int(hsPayload[3])
	if hsLen > maxSNIPeekBytes {
		return "", false, fmt.Errorf("TLS ClientHello too large (%d)", hsLen)
	}
	if len(hsPayload) < 4+hsLen {
		return "", true, nil
	}

	body := hsPayload[4 : 4+hsLen]
	// legacy_version (2) + random (32) = 34
	if len(body) < 34+1 {
		return "", false, nil
	}
	pos := 34
	sessIDLen := int(body[pos])
	pos++
	if pos+sessIDLen+2 > len(body) {
		return "", false, nil
	}
	pos += sessIDLen

	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+cipherLen+1 > len(body) {
		return "", false, nil
	}
	pos += cipherLen

	compLen := int(body[pos])
	pos++
	if pos+compLen > len(body) {
		return "", false, nil
	}
	pos += compLen

	if pos+2 > len(body) {
		return "", false, nil // no extensions
	}
	extTotal := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extTotal > len(body) {
		extTotal = len(body) - pos
	}
	extEnd := pos + extTotal

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		if extType == 0x0000 && extLen >= 2 { // server_name extension
			sniData := body[pos : pos+extLen]
			listLen := int(binary.BigEndian.Uint16(sniData[0:2]))
			if 2+listLen > len(sniData) {
				listLen = len(sniData) - 2
			}
			p := 2
			for p+3 <= 2+listLen {
				nameType := sniData[p]
				nameLen := int(binary.BigEndian.Uint16(sniData[p+1 : p+3]))
				p += 3
				if p+nameLen > 2+listLen {
					break
				}
				if nameType == 0x00 { // host_name
					return string(sniData[p : p+nameLen]), false, nil
				}
				p += nameLen
			}
		}
		pos += extLen
	}
	return "", false, nil
}

// DomainsOverlap reports whether two normalized domain patterns (exact or "*.suffix") can match any common hostname.
// Master uses this to prevent two rules on a shared port from colliding or hijacking each other's domains.
func DomainsOverlap(a, b string) bool {
	a = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a), "."))
	b = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(b), "."))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	aWild := strings.HasPrefix(a, "*.")
	bWild := strings.HasPrefix(b, "*.")
	if aWild && bWild {
		// "*.example.com" and "*.sub.example.com" overlap on "x.sub.example.com"
		aSuf := a[1:] // ".example.com"
		bSuf := b[1:] // ".sub.example.com"
		return strings.HasSuffix(aSuf, bSuf) || strings.HasSuffix(bSuf, aSuf)
	}
	if aWild {
		aSuf := a[1:] // ".example.com"
		return strings.HasSuffix(b, aSuf) && len(b) > len(aSuf)
	}
	if bWild {
		bSuf := b[1:]
		return strings.HasSuffix(a, bSuf) && len(a) > len(bSuf)
	}
	return false
}

type sniRouteEntry struct {
	ruleKey  string
	patterns []string
	inst     *nativeRuleInstance
	ruleCtx  context.Context
}

// sniHostRouter multiplexes multiple MatchDomains rules over one shared TCP listener on (listenHost, listenPort).
type sniHostRouter struct {
	bindAddr string
	ln       net.Listener
	cancel   context.CancelFunc

	mu     sync.RWMutex
	routes map[string]*sniRouteEntry // ruleKey -> entry
}

func newSNIHostRouter(bindAddr string, engine *NativeEngine) (*sniHostRouter, error) {
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("shared SNI/Host TCP listen %s failed: %w", bindAddr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	rt := &sniHostRouter{
		bindAddr: bindAddr,
		ln:       ln,
		cancel:   cancel,
		routes:   make(map[string]*sniRouteEntry),
	}
	go rt.acceptLoop(ctx, engine)
	return rt, nil
}

func (rt *sniHostRouter) Register(ruleKey string, ruleCtx context.Context, inst *nativeRuleInstance) error {
	domains, err := security.ParseAndValidateMatchDomains(inst.spec.MatchDomains)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for otherKey, entry := range rt.routes {
		if otherKey == ruleKey {
			continue
		}
		for _, p1 := range domains {
			for _, p2 := range entry.patterns {
				if DomainsOverlap(p1, p2) {
					return fmt.Errorf("shared-port domain %q overlaps with active rule %s (%q)", p1, otherKey, p2)
				}
			}
		}
	}
	rt.routes[ruleKey] = &sniRouteEntry{
		ruleKey:  ruleKey,
		patterns: domains,
		inst:     inst,
		ruleCtx:  ruleCtx,
	}
	return nil
}

// Unregister removes a rule from the router and reports whether the router now has zero routes and should be closed.
func (rt *sniHostRouter) Unregister(ruleKey string) bool {
	rt.mu.Lock()
	delete(rt.routes, ruleKey)
	empty := len(rt.routes) == 0
	rt.mu.Unlock()
	if empty {
		rt.cancel()
		_ = rt.ln.Close()
	}
	return empty
}

func (rt *sniHostRouter) matchHost(host string) (*sniRouteEntry, bool) {
	if host == "" {
		return nil, false
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var bestWild *sniRouteEntry
	bestWildLen := -1
	for _, entry := range rt.routes {
		for _, pat := range entry.patterns {
			if pat == host {
				return entry, true
			}
			if strings.HasPrefix(pat, "*.") {
				suf := pat[1:] // ".example.com"
				if strings.HasSuffix(host, suf) && len(host) > len(suf) && len(pat) > bestWildLen {
					bestWild = entry
					bestWildLen = len(pat)
				}
			}
		}
	}
	if bestWild != nil {
		return bestWild, true
	}
	return nil, false
}

func (rt *sniHostRouter) acceptLoop(ctx context.Context, engine *NativeEngine) {
	peekSem := make(chan struct{}, 512)
	for {
		conn, err := rt.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(30 * time.Millisecond)
				continue
			}
		}
		releaseIP, allowed := engine.connGuard.Acquire(conn.RemoteAddr())
		if !allowed {
			_ = conn.Close()
			continue
		}
		select {
		case peekSem <- struct{}{}:
		default:
			releaseIP()
			_ = conn.Close()
			continue
		}
		go func(c net.Conn, rel func()) {
			setTCPKeepAlive(c)
			host, replayed, err := ExtractSNIOrHost(c, 5*time.Second)
			<-peekSem
			if err != nil || host == "" {
				rel()
				_ = c.Close()
				return
			}
			entry, ok := rt.matchHost(host)
			if !ok {
				rel()
				_ = c.Close()
				return
			}
			engine.dispatchMatchedTCPConn(entry.ruleCtx, entry.inst, replayed, rel)
		}(conn, releaseIP)
	}
}
