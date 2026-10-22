package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

const (
	pcapMagic       = 0xa1b2c3d4 // microsecond timestamps
	pcapSnapLen     = 65535
	pcapLinkRawIP   = 101 // LINKTYPE_RAW: packets start at the IPv4/IPv6 header
	ipProtoUDP      = 17
	ipv4HeaderLen   = 20
	ipv6HeaderLen   = 40
	udpHeaderLen    = 8
	defaultIPv4TTL  = 64
	maxUDPPayloadV4 = 65535 - ipv4HeaderLen - udpHeaderLen
)

// Capture records the UDP datagrams exchanged over wrapped connections into a
// pcap file. Packets are reconstructed from the application-level payloads
// (raw-IP link type, synthetic IP/UDP headers with valid checksums), so no
// privileges or libpcap are needed. A nil *Capture is valid and records nothing.
type Capture struct {
	mu   sync.Mutex
	f    *os.File
	path string
	ipID uint16
}

// NewCapture creates ./sterak-<timestamp>.pcap and writes the pcap header.
func NewCapture() (*Capture, error) {
	path := fmt.Sprintf("sterak-%s.pcap", time.Now().Format("20060102-150405"))
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap file: %w", err)
	}

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:], 2) // version major
	binary.LittleEndian.PutUint16(hdr[6:], 4) // version minor
	binary.LittleEndian.PutUint32(hdr[16:], pcapSnapLen)
	binary.LittleEndian.PutUint32(hdr[20:], pcapLinkRawIP)
	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to write pcap header: %w", err)
	}
	return &Capture{f: f, path: path}, nil
}

func (c *Capture) Path() string { return c.path }

func (c *Capture) Close() error {
	if c == nil {
		return nil
	}
	return c.f.Close()
}

// Wrap returns conn with every successful Read/Write recorded. Connections
// that are not connected UDP sockets are returned unchanged.
func (c *Capture) Wrap(conn net.Conn) net.Conn {
	if c == nil {
		return conn
	}
	local, ok1 := conn.LocalAddr().(*net.UDPAddr)
	remote, ok2 := conn.RemoteAddr().(*net.UDPAddr)
	if !ok1 || !ok2 {
		return conn
	}
	return &capturedConn{Conn: conn, cap: c, local: local, remote: remote}
}

type capturedConn struct {
	net.Conn
	cap           *Capture
	local, remote *net.UDPAddr
}

func (cc *capturedConn) Write(p []byte) (int, error) {
	n, err := cc.Conn.Write(p)
	if n > 0 {
		cc.cap.record(time.Now(), cc.local, cc.remote, p[:n])
	}
	return n, err
}

func (cc *capturedConn) Read(p []byte) (int, error) {
	n, err := cc.Conn.Read(p)
	if err == nil {
		cc.cap.record(time.Now(), cc.remote, cc.local, p[:n])
	}
	return n, err
}

// record appends one src->dst UDP datagram to the file. Capture errors are
// not fatal to the test run, so they are dropped.
func (c *Capture) record(ts time.Time, src, dst *net.UDPAddr, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ipID++
	pkt := buildUDPPacket(src, dst, payload, c.ipID)
	if pkt == nil {
		return
	}

	rec := make([]byte, 16, 16+len(pkt))
	binary.LittleEndian.PutUint32(rec[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
	rec = append(rec, pkt...)
	c.f.Write(rec)
}

// buildUDPPacket returns an IPv4 or IPv6 packet carrying payload in UDP, or
// nil if the addresses are not of the same family or the payload is too large.
func buildUDPPacket(src, dst *net.UDPAddr, payload []byte, id uint16) []byte {
	s4, d4 := src.IP.To4(), dst.IP.To4()
	udpLen := udpHeaderLen + len(payload)

	if s4 != nil && d4 != nil {
		if len(payload) > maxUDPPayloadV4 {
			return nil
		}
		pkt := make([]byte, ipv4HeaderLen+udpLen)
		pkt[0] = 0x45 // v4, IHL 5
		binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
		binary.BigEndian.PutUint16(pkt[4:], id)
		binary.BigEndian.PutUint16(pkt[6:], 0x4000) // DF
		pkt[8] = defaultIPv4TTL
		pkt[9] = ipProtoUDP
		copy(pkt[12:], s4)
		copy(pkt[16:], d4)
		binary.BigEndian.PutUint16(pkt[10:], ^checksum(pkt[:ipv4HeaderLen], 0))

		fillUDP(pkt[ipv4HeaderLen:], src, dst, payload, s4, d4)
		return pkt
	}

	s6, d6 := src.IP.To16(), dst.IP.To16()
	if s4 != nil || d4 != nil || s6 == nil || d6 == nil || udpLen > 0xffff {
		return nil
	}
	pkt := make([]byte, ipv6HeaderLen+udpLen)
	pkt[0] = 0x60 // v6
	binary.BigEndian.PutUint16(pkt[4:], uint16(udpLen))
	pkt[6] = ipProtoUDP
	pkt[7] = 64 // hop limit
	copy(pkt[8:], s6)
	copy(pkt[24:], d6)
	fillUDP(pkt[ipv6HeaderLen:], src, dst, payload, s6, d6)
	return pkt
}

// fillUDP writes the UDP header and payload into seg and computes the
// checksum over the pseudo-header made of srcIP/dstIP.
func fillUDP(seg []byte, src, dst *net.UDPAddr, payload, srcIP, dstIP []byte) {
	binary.BigEndian.PutUint16(seg[0:], uint16(src.Port))
	binary.BigEndian.PutUint16(seg[2:], uint16(dst.Port))
	binary.BigEndian.PutUint16(seg[4:], uint16(len(seg)))
	copy(seg[udpHeaderLen:], payload)

	pseudo := make([]byte, 0, 2*len(srcIP)+8)
	pseudo = append(pseudo, srcIP...)
	pseudo = append(pseudo, dstIP...)
	pseudo = append(pseudo, 0, ipProtoUDP, byte(len(seg)>>8), byte(len(seg)))

	sum := ^checksum(seg, checksum(pseudo, 0))
	if sum == 0 {
		sum = 0xffff // 0 means "no checksum" in UDP
	}
	binary.BigEndian.PutUint16(seg[6:], sum)
}

// checksum returns the (non-inverted) 16-bit ones'-complement sum of b added
// to initial.
func checksum(b []byte, initial uint16) uint16 {
	sum := uint32(initial)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}
