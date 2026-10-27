package turn

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/stun"
)

// ErrorResponse is a STUN/TURN error response (RFC 5766 §6-§11 error codes).
type ErrorResponse struct {
	Method stun.Method
	Code   int
	Reason string
	Msg    *stun.Message
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("%s error %d %s", e.Method, e.Code, e.Reason)
}

const (
	codeUnauthorized = 401
	codeStaleNonce   = 438
)

// setterFunc adapts a function to stun.Setter.
type setterFunc func(m *stun.Message) error

func (f setterFunc) AddTo(m *stun.Message) error { return f(m) }

// rawAttr adds an attribute with a pre-encoded value.
func rawAttr(t stun.AttrType, v []byte) stun.Setter {
	return setterFunc(func(m *stun.Message) error {
		m.Add(t, v)
		return nil
	})
}

// xorAddr adds an XOR-encoded address attribute (XOR-PEER-ADDRESS, ...).
func xorAddr(t stun.AttrType, addr *net.UDPAddr) stun.Setter {
	return setterFunc(func(m *stun.Message) error {
		return stun.XORMappedAddress{IP: addr.IP, Port: addr.Port}.AddToAs(m, t)
	})
}

// requestedTransportUDP is REQUESTED-TRANSPORT = UDP (17) + 3 RFFU bytes.
func requestedTransportUDP() stun.Setter {
	return rawAttr(stun.AttrRequestedTransport, []byte{17, 0, 0, 0})
}

// lifetime is the LIFETIME attribute, in seconds.
func lifetime(seconds uint32) stun.Setter {
	return setterFunc(func(m *stun.Message) error {
		v := make([]byte, 4)
		v[0], v[1], v[2], v[3] = byte(seconds>>24), byte(seconds>>16), byte(seconds>>8), byte(seconds)
		m.Add(stun.AttrLifetime, v)
		return nil
	})
}

// channelNumber is CHANNEL-NUMBER: 16-bit channel + 16 RFFU bits.
func channelNumber(ch uint16) stun.Setter {
	return rawAttr(stun.AttrChannelNumber, []byte{byte(ch >> 8), byte(ch), 0, 0})
}

// channelData frames payload as a ChannelData message (RFC 5766 §11.4):
// 2-byte channel number, 2-byte payload length, payload. Padding is optional
// over UDP and omitted.
func channelData(ch uint16, payload []byte) []byte {
	b := make([]byte, 4+len(payload))
	b[0], b[1] = byte(ch>>8), byte(ch)
	b[2], b[3] = byte(len(payload)>>8), byte(len(payload))
	copy(b[4:], payload)
	return b
}

// sendIndication builds a Send indication (RFC 5766 §10.1) asking the server
// to relay payload to peer. Indications carry no credentials and get no reply.
func sendIndication(peer *net.UDPAddr, payload []byte) ([]byte, error) {
	m, err := stun.Build(
		stun.TransactionID,
		stun.NewType(stun.MethodSend, stun.ClassIndication),
		xorAddr(stun.AttrXORPeerAddress, peer),
		rawAttr(stun.AttrData, payload),
	)
	if err != nil {
		return nil, fmt.Errorf("building send indication: %w", err)
	}
	return m.Raw, nil
}

// conn is a connected UDP socket speaking TURN request/response transactions.
type conn struct {
	c       net.Conn
	timeout time.Duration
	buf     []byte
}

func newConn(c net.Conn, timeout time.Duration) *conn {
	return &conn{c: c, timeout: timeout, buf: make([]byte, 65535)}
}

// send writes one datagram without waiting for a reply (ChannelData has no
// response).
func (c *conn) send(b []byte) error {
	_, err := c.c.Write(b)
	return err
}

// do sends req and waits for the response carrying the same transaction ID.
// Unrelated datagrams (indications, ChannelData, late replies) are skipped.
// A STUN error response is returned as *ErrorResponse together with the
// message.
func (c *conn) do(req *stun.Message) (*stun.Message, error) {
	start := time.Now()
	if _, err := c.c.Write(req.Raw); err != nil {
		return nil, err
	}
	if err := c.c.SetReadDeadline(start.Add(c.timeout)); err != nil {
		return nil, err
	}
	for {
		n, err := c.c.Read(c.buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, fmt.Errorf("%s: no response within %s", req.Type.Method, c.timeout)
			}
			return nil, err
		}
		if !stun.IsMessage(c.buf[:n]) {
			continue
		}
		res := &stun.Message{Raw: append([]byte(nil), c.buf[:n]...)}
		if err := res.Decode(); err != nil {
			continue
		}
		if res.TransactionID != req.TransactionID || res.Type.Method != req.Type.Method {
			continue
		}
		switch res.Type.Class {
		case stun.ClassSuccessResponse:
			return res, nil
		case stun.ClassErrorResponse:
			er := &ErrorResponse{Method: res.Type.Method, Msg: res}
			var code stun.ErrorCodeAttribute
			if err := code.GetFrom(res); err != nil {
				return res, fmt.Errorf("%s error response without ERROR-CODE: %w", res.Type.Method, err)
			}
			er.Code, er.Reason = int(code.Code), string(code.Reason)
			return res, er
		}
	}
}
