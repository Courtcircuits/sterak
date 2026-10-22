package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/stun"
	"github.com/schollz/progressbar/v3"
)

type MalformedStun struct {
	Cfg Config
}

const (
	stunHeaderSize  = 20
	stunMagicCookie = 0x2112A442
	stunBindingReq  = 0x0001
)

// malformedCase builds one kind of invalid (or borderline) STUN datagram.
type malformedCase struct {
	name  string
	build func() []byte
}

// header returns a 20-byte STUN header with a fresh transaction ID.
func header(msgType, length uint16, cookie uint32) []byte {
	b := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(b[0:2], msgType)
	binary.BigEndian.PutUint16(b[2:4], length)
	binary.BigEndian.PutUint32(b[4:8], cookie)
	id := stun.NewTransactionID()
	copy(b[8:], id[:])
	return b
}

// attr encodes a TLV attribute, padded to a 4-byte boundary. declaredLen lets
// the caller lie about the value length.
func attr(attrType uint16, value []byte, declaredLen uint16) []byte {
	b := make([]byte, 4, 4+len(value)+3)
	binary.BigEndian.PutUint16(b[0:2], attrType)
	binary.BigEndian.PutUint16(b[2:4], declaredLen)
	b = append(b, value...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

var malformedCases = []malformedCase{
	{"empty datagram", func() []byte { return []byte{} }},
	{"1 byte", func() []byte { return randomBytes(1) }},
	{"truncated header (19 bytes)", func() []byte { return header(stunBindingReq, 0, stunMagicCookie)[:stunHeaderSize-1] }},
	{"random garbage (20 bytes)", func() []byte { return randomBytes(20) }},
	{"random garbage (512 bytes)", func() []byte { return randomBytes(512) }},
	{"wrong magic cookie", func() []byte { return header(stunBindingReq, 0, 0xDEADBEEF) }},
	{"zero magic cookie (RFC 3489 style)", func() []byte { return header(stunBindingReq, 0, 0) }},
	{"top two bits set in message type", func() []byte { return header(0xC001, 0, stunMagicCookie) }},
	{"unknown method", func() []byte { return header(0x0FF1, 0, stunMagicCookie) }},
	{"length > payload", func() []byte { return header(stunBindingReq, 64, stunMagicCookie) }},
	{"length < payload", func() []byte {
		return append(header(stunBindingReq, 0, stunMagicCookie), randomBytes(16)...)
	}},
	{"length not multiple of 4", func() []byte {
		return append(header(stunBindingReq, 5, stunMagicCookie), randomBytes(5)...)
	}},
	{"max length field, no payload", func() []byte { return header(stunBindingReq, 0xFFFF, stunMagicCookie) }},
	{"truncated attribute header", func() []byte {
		return append(header(stunBindingReq, 2, stunMagicCookie), 0x00, 0x20)
	}},
	{"attribute length overflows message", func() []byte {
		a := attr(stun.AttrSoftware.Value(), []byte("abcd"), 0x1000)
		return append(header(stunBindingReq, uint16(len(a)), stunMagicCookie), a...)
	}},
	{"unknown comprehension-required attribute", func() []byte {
		a := attr(0x7FFF, []byte{1, 2, 3, 4}, 4)
		return append(header(stunBindingReq, uint16(len(a)), stunMagicCookie), a...)
	}},
	{"bad FINGERPRINT", func() []byte {
		a := attr(stun.AttrFingerprint.Value(), []byte{0xDE, 0xAD, 0xBE, 0xEF}, 4)
		return append(header(stunBindingReq, uint16(len(a)), stunMagicCookie), a...)
	}},
	{"bad MESSAGE-INTEGRITY length", func() []byte {
		a := attr(stun.AttrMessageIntegrity.Value(), randomBytes(4), 4)
		return append(header(stunBindingReq, uint16(len(a)), stunMagicCookie), a...)
	}},
	{"binding indication-class garbage body", func() []byte {
		body := randomBytes(64)
		return append(header(0x0011, uint16(len(body)), stunMagicCookie), body...)
	}},
}

type caseStats struct {
	sent      int
	responses int
	lastReply string
}

func (ms MalformedStun) Run() ([]result, error) {
	cfg := ms.Cfg

	addr, err := net.ResolveUDPAddr("udp", cfg.stunHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN host: %w", err)
	}

	results := make([]result, cfg.runCount)
	stats := make([]caseStats, len(malformedCases))

	fmt.Println("Starting malformed STUN requests...")
	bar := progressbar.Default(int64(cfg.runCount))

	for i := range cfg.runCount {
		idx := i % len(malformedCases)
		reply, elapsed, err := sendRaw(addr, malformedCases[idx].build(), cfg.timeout, cfg.capture)

		// A dropped packet shows up as a timeout error; a reply (even an
		// error response) is a success from the transport's point of view.
		results[i] = result{time: elapsed, err: err}
		stats[idx].sent++
		if err == nil {
			stats[idx].responses++
			stats[idx].lastReply = describeReply(reply)
		}

		bar.Add(1)
	}

	fmt.Println() // New line after progress bar
	printMalformedSummary(stats)
	return results, nil
}

// sendRaw sends payload over a fresh UDP socket (so a late reply to a previous
// request cannot be mistaken for this one) and waits for a single reply.
func sendRaw(addr *net.UDPAddr, payload []byte, timeout time.Duration, capture *Capture) ([]byte, int64, error) {
	udp, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to dial STUN server: %w", err)
	}
	defer udp.Close()
	conn := capture.Wrap(udp)

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return nil, time.Since(start).Microseconds(), err
	}

	if err := conn.SetReadDeadline(start.Add(timeout)); err != nil {
		return nil, time.Since(start).Microseconds(), err
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	elapsed := time.Since(start).Microseconds()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, elapsed, fmt.Errorf("no response within %s", timeout)
		}
		return nil, elapsed, err
	}
	return buf[:n], elapsed, nil
}

func describeReply(b []byte) string {
	m := &stun.Message{Raw: b}
	if err := m.Decode(); err != nil {
		return fmt.Sprintf("%d bytes, undecodable (%v)", len(b), err)
	}
	desc := m.Type.String()
	if m.Type.Class == stun.ClassErrorResponse {
		var code stun.ErrorCodeAttribute
		if err := code.GetFrom(m); err == nil {
			desc += fmt.Sprintf(" (%d %s)", code.Code, code.Reason)
		}
	}
	return desc
}

func printMalformedSummary(stats []caseStats) {
	fmt.Println("Server behaviour per malformed case:")
	for i, c := range malformedCases {
		s := stats[i]
		if s.sent == 0 {
			continue
		}
		outcome := "dropped"
		if s.responses > 0 {
			outcome = "replied: " + s.lastReply
		}
		fmt.Printf("  %-42s %d/%d replies  %s\n", c.name, s.responses, s.sent, outcome)
	}
}
