package engine

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var proxyV2Sig = [12]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

func parseHostPortIP(raw string) (net.IP, int, bool) {
	h, pStr, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	if ip == nil {
		return nil, 0, false
	}
	p, err := strconv.Atoi(pStr)
	if err != nil || p < 0 || p > 65535 {
		return nil, 0, false
	}
	return ip, p, true
}

func addrToIPPort(a net.Addr) (net.IP, int, bool) {
	if a == nil {
		return nil, 0, false
	}
	switch v := a.(type) {
	case *net.TCPAddr:
		if v.IP != nil {
			return v.IP, v.Port, true
		}
	case *net.UDPAddr:
		if v.IP != nil {
			return v.IP, v.Port, true
		}
	}
	return parseHostPortIP(a.String())
}

// BuildProxyProtocolHeader constructs a HAProxy PROXY protocol v1 or v2 header carrying the original client IP:port
// and destination IP:port. Supports both IPv4 and IPv6 (automatically normalizing mixed families to IPv6-mapped IPv4).
func BuildProxyProtocolHeader(version int, proto string, clientAddrStr string, dstAddr net.Addr) ([]byte, error) {
	if version != 1 && version != 2 {
		return nil, nil
	}
	srcIP, srcPort, srcOK := parseHostPortIP(clientAddrStr)
	dstIP, dstPort, dstOK := addrToIPPort(dstAddr)
	if !srcOK {
		if version == 1 {
			return []byte("PROXY UNKNOWN\r\n"), nil
		}
		var hdr [16]byte
		copy(hdr[:12], proxyV2Sig[:])
		hdr[12] = 0x20 // v2 LOCAL / UNSPEC
		hdr[13] = 0x00
		return hdr[:], nil
	}
	if !dstOK {
		if srcIP.To4() != nil {
			dstIP = net.IPv4zero
		} else {
			dstIP = net.IPv6zero
		}
		dstPort = 0
	}

	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	isV4 := src4 != nil && dst4 != nil

	if version == 1 {
		if isV4 {
			return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", src4.String(), dst4.String(), srcPort, dstPort)), nil
		}
		s16 := srcIP.To16()
		d16 := dstIP.To16()
		return []byte(fmt.Sprintf("PROXY TCP6 %s %s %d %d\r\n", s16.String(), d16.String(), srcPort, dstPort)), nil
	}

	// PROXY Protocol v2 binary header
	sockProto := byte(0x01) // STREAM (TCP)
	if strings.EqualFold(proto, "udp") {
		sockProto = 0x02 // DGRAM (UDP)
	}
	if isV4 {
		buf := make([]byte, 16+12)
		copy(buf[:12], proxyV2Sig[:])
		buf[12] = 0x21               // version 2, PROXY command
		buf[13] = 0x10 | sockProto   // AF_INET | STREAM/DGRAM
		binary.BigEndian.PutUint16(buf[14:16], 12)
		copy(buf[16:20], src4)
		copy(buf[20:24], dst4)
		binary.BigEndian.PutUint16(buf[24:26], uint16(srcPort))
		binary.BigEndian.PutUint16(buf[26:28], uint16(dstPort))
		return buf, nil
	}

	s16 := srcIP.To16()
	d16 := dstIP.To16()
	buf := make([]byte, 16+36)
	copy(buf[:12], proxyV2Sig[:])
	buf[12] = 0x21             // version 2, PROXY command
	buf[13] = 0x20 | sockProto // AF_INET6 | STREAM/DGRAM
	binary.BigEndian.PutUint16(buf[14:16], 36)
	copy(buf[16:32], s16)
	copy(buf[32:48], d16)
	binary.BigEndian.PutUint16(buf[48:50], uint16(srcPort))
	binary.BigEndian.PutUint16(buf[50:52], uint16(dstPort))
	return buf, nil
}

// WriteProxyProtocolHeader writes the PROXY protocol v1 or v2 header onto targetConn with a bounded write deadline.
func WriteProxyProtocolHeader(targetConn net.Conn, version int, proto string, clientAddrStr string) error {
	if version != 1 && version != 2 {
		return nil
	}
	hdr, err := BuildProxyProtocolHeader(version, proto, clientAddrStr, targetConn.RemoteAddr())
	if err != nil || len(hdr) == 0 {
		return err
	}
	_ = targetConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, wErr := targetConn.Write(hdr)
	_ = targetConn.SetWriteDeadline(time.Time{})
	return wErr
}

// ParseProxyProtocolHeader parses a PROXY protocol v1 or v2 header from r and returns (version, clientAddr, dstAddr, err).
func ParseProxyProtocolHeader(r *bufio.Reader) (int, string, string, error) {
	sig, err := r.Peek(6)
	if err != nil {
		return 0, "", "", err
	}
	if bytes.Equal(sig, []byte("PROXY ")) {
		var rawLine [108]byte
		n := 0
		foundLF := false
		for n < len(rawLine) {
			b, bErr := r.ReadByte()
			if bErr != nil {
				return 0, "", "", bErr
			}
			rawLine[n] = b
			n++
			if b == '\n' {
				foundLF = true
				break
			}
		}
		if !foundLF || n < 8 || rawLine[n-2] != '\r' {
			return 0, "", "", fmt.Errorf("malformed or oversized PROXY v1 line")
		}
		line := string(rawLine[:n-2])
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == "UNKNOWN" {
			return 1, "", "", nil
		}
		if len(parts) != 6 || (parts[1] != "TCP4" && parts[1] != "TCP6") {
			return 0, "", "", fmt.Errorf("invalid PROXY v1 header fields")
		}
		srcIP := net.ParseIP(parts[2])
		dstIP := net.ParseIP(parts[3])
		if srcIP == nil || dstIP == nil {
			return 0, "", "", fmt.Errorf("invalid PROXY v1 IP address")
		}
		if parts[1] == "TCP4" && (srcIP.To4() == nil || dstIP.To4() == nil) {
			return 0, "", "", fmt.Errorf("PROXY v1 TCP4 requires IPv4 addresses")
		}
		if parts[1] == "TCP6" && (srcIP.To4() != nil || dstIP.To4() != nil) {
			return 0, "", "", fmt.Errorf("PROXY v1 TCP6 requires IPv6 addresses")
		}
		sPort, err1 := strconv.ParseUint(parts[4], 10, 16)
		dPort, err2 := strconv.ParseUint(parts[5], 10, 16)
		if err1 != nil || err2 != nil {
			return 0, "", "", fmt.Errorf("invalid PROXY v1 port")
		}
		src := net.JoinHostPort(srcIP.String(), strconv.FormatUint(sPort, 10))
		dst := net.JoinHostPort(dstIP.String(), strconv.FormatUint(dPort, 10))
		return 1, src, dst, nil
	}

	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, "", "", err
	}
	if !bytes.Equal(hdr[:12], proxyV2Sig[:]) {
		return 0, "", "", fmt.Errorf("not a PROXY v1 or v2 header")
	}
	if (hdr[12] & 0xF0) != 0x20 {
		return 0, "", "", fmt.Errorf("unsupported PROXY v2 version byte 0x%x", hdr[12])
	}
	addrLen := int(binary.BigEndian.Uint16(hdr[14:16]))
	if addrLen > 512 {
		return 0, "", "", fmt.Errorf("PROXY v2 address block too large (%d)", addrLen)
	}
	addrBuf := make([]byte, addrLen)
	if addrLen > 0 {
		if _, err := io.ReadFull(r, addrBuf); err != nil {
			return 0, "", "", err
		}
	}
	if (hdr[12] & 0x0F) == 0x00 { // LOCAL
		return 2, "", "", nil
	}
	fam := hdr[13] & 0xF0
	switch fam {
	case 0x10: // AF_INET
		if addrLen < 12 {
			return 0, "", "", fmt.Errorf("short PROXY v2 IPv4 block")
		}
		sIP := net.IP(addrBuf[0:4]).String()
		dIP := net.IP(addrBuf[4:8]).String()
		sPort := binary.BigEndian.Uint16(addrBuf[8:10])
		dPort := binary.BigEndian.Uint16(addrBuf[10:12])
		return 2, net.JoinHostPort(sIP, strconv.Itoa(int(sPort))), net.JoinHostPort(dIP, strconv.Itoa(int(dPort))), nil
	case 0x20: // AF_INET6
		if addrLen < 36 {
			return 0, "", "", fmt.Errorf("short PROXY v2 IPv6 block")
		}
		sIP := net.IP(addrBuf[0:16]).String()
		dIP := net.IP(addrBuf[16:32]).String()
		sPort := binary.BigEndian.Uint16(addrBuf[32:34])
		dPort := binary.BigEndian.Uint16(addrBuf[34:36])
		return 2, net.JoinHostPort(sIP, strconv.Itoa(int(sPort))), net.JoinHostPort(dIP, strconv.Itoa(int(dPort))), nil
	default:
		return 2, "", "", nil
	}
}
