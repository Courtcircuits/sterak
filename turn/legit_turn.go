package turn

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Courtcircuits/sterak/capture"
	"github.com/Courtcircuits/sterak/config"
	"github.com/pion/stun"
	"github.com/schollz/progressbar/v3"
)

// Operation names used in Result.Method, in the order a session issues them.
const (
	OpAllocateChallenge  = "allocate-challenge" // unauthenticated Allocate answered with 401
	OpAllocate           = "allocate"
	OpCreatePermission   = "create-permission"
	OpChannelBind        = "channel-bind"
	OpChannelData        = "channel-data"                 // ChannelData send (only with Cfg.ChannelData)
	OpPeerChannelData    = "peer-receive-channel-data"    // that payload arriving at the peer (only with Cfg.PeerListen)
	OpSendIndication     = "send-indication"              // Send indication send (only with Cfg.SendIndication)
	OpPeerSendIndication = "peer-receive-send-indication" // that payload arriving at the peer (only with Cfg.PeerListen)
)

// Operations lists the measured operations in session order.
var Operations = []string{
	OpAllocateChallenge, OpAllocate, OpCreatePermission, OpChannelBind,
	OpChannelData, OpPeerChannelData, OpSendIndication, OpPeerSendIndication,
}

// firstChannel is the lowest valid channel number (RFC 5766 §11).
const firstChannel uint16 = 0x4000

// maxChannelDataPayload is the largest payload that fits one UDP datagram
// after the 4-byte ChannelData header (65535 - 8 UDP - 20 IPv4 - 4).
const maxChannelDataPayload = 65507 - 4

// maxSendIndicationPayload is the largest payload that fits one UDP datagram
// in a Send indication: 20 STUN header + 24 XOR-PEER-ADDRESS (IPv6 worst
// case) + 4 DATA header, with the payload padded to a multiple of 4.
const maxSendIndicationPayload = (65507 - 20 - 24 - 4) &^ 3

// Result is the outcome of a single TURN transaction.
type Result struct {
	Method string
	Time   int64 // microseconds
	Err    error
}

// LegitTurn drives well-formed TURN sessions. Each session uses a fresh UDP
// socket (hence a fresh 5-tuple) and performs:
//
//	Allocate (unauthenticated, expecting 401) -> Allocate (long-term credentials)
//	-> CreatePermission -> ChannelBind -> [ChannelData] -> [Send indication]
//	-> Refresh(0) to free the allocation.
//
// ChannelData / Send indication are sent only when Cfg.ChannelData /
// Cfg.SendIndication are set. Their latency is the local send time: the server
// does not acknowledge them. With Cfg.PeerListen, a peer-receive result is
// recorded per send, measuring send to arrival at the peer and failing if the
// payload does not arrive intact. The Refresh(0) cleanup is best-effort and
// not measured.
type LegitTurn struct {
	Cfg     config.Config
	Capture *capture.Capture
}

func (lt LegitTurn) Run() ([]Result, error) {
	cfg := lt.Cfg

	hostPort, err := cfg.HostPort()
	if err != nil {
		return nil, err
	}
	server, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve TURN host: %w", err)
	}

	sends := cfg.ChannelData || cfg.SendIndication
	if cfg.PeerListen != "" && !sends {
		return nil, errors.New("peer_listen needs channel_data or send_indication: nothing would be sent to the peer")
	}

	var size int
	if sends {
		size = cfg.DataSize
		if size == 0 {
			size = config.DefaultTURNDataSize
		}
		limit := maxChannelDataPayload
		if cfg.SendIndication {
			limit = min(limit, maxSendIndicationPayload)
		}
		if size < 0 || size > limit {
			return nil, fmt.Errorf("invalid data size %d (want 1-%d)", size, limit)
		}
	}

	var ln *peerListener
	if cfg.PeerListen != "" {
		ln, err = newPeerListener(cfg.PeerListen)
		if err != nil {
			return nil, err
		}
		defer ln.Close()
	}

	peerStr := cfg.Peer
	switch {
	case peerStr != "":
	case ln != nil:
		if ln.Addr().IP.IsUnspecified() {
			return nil, fmt.Errorf("peer_listen %q is a wildcard address: set peer to an address the TURN server can reach", cfg.PeerListen)
		}
		peerStr = ln.Addr().String()
	default:
		peerStr = config.DefaultTURNPeer
	}
	peer, err := net.ResolveUDPAddr("udp", peerStr)
	if err != nil {
		return nil, fmt.Errorf("invalid TURN peer %q: %w", peerStr, err)
	}

	workers := max(cfg.Concurrency, 1)

	fmt.Println("Starting TURN sessions...")
	bar := progressbar.Default(int64(cfg.RunCount * workers))

	var (
		mu      sync.Mutex
		results = make([]Result, 0, cfg.RunCount*workers*len(Operations))
		wg      sync.WaitGroup
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range cfg.RunCount {
				res := lt.session(server, peer, ln, size)

				mu.Lock()
				results = append(results, res...)
				mu.Unlock()

				bar.Add(1)
				time.Sleep(cfg.Rate)
			}
		}()
	}
	wg.Wait()

	fmt.Println() // New line after progress bar
	return results, nil
}

// session runs one allocate/permission/bind sequence, plus the configured
// ChannelData / Send indication sends, and returns one Result per transaction
// attempted. size is the payload size of those sends.
func (lt LegitTurn) session(server, peer *net.UDPAddr, ln *peerListener, size int) []Result {
	var out []Result
	record := func(method string, d time.Duration, err error) {
		out = append(out, Result{Method: method, Time: d.Microseconds(), Err: err})
	}

	raw, err := net.DialUDP("udp", nil, server)
	if err != nil {
		record(OpAllocate, 0, fmt.Errorf("failed to dial TURN server: %w", err))
		return out
	}
	defer raw.Close()

	s := &session{
		conn:     newConn(lt.Capture.Wrap(raw), lt.Cfg.Timeout),
		username: lt.Cfg.Username,
		password: lt.Cfg.Password,
	}

	// Allocate: first without credentials, as a real client does.
	res, d, err := s.exec(stun.MethodAllocate, requestedTransportUDP())
	var er *ErrorResponse
	if errors.As(err, &er) && er.Code == codeUnauthorized {
		record(OpAllocateChallenge, d, nil)
		if s.username == "" {
			record(OpAllocate, 0, errors.New("server requires authentication: set username and password"))
			return out
		}
		if err := s.learn(er.Msg); err != nil {
			record(OpAllocate, 0, err)
			return out
		}
		res, d, err = s.exec(stun.MethodAllocate, requestedTransportUDP())
	}
	if err == nil {
		var relayed stun.XORMappedAddress
		if gerr := relayed.GetFromAs(res, stun.AttrXORRelayedAddress); gerr != nil {
			err = fmt.Errorf("allocate success without XOR-RELAYED-ADDRESS: %w", gerr)
		}
	}
	record(OpAllocate, d, err)
	if err != nil {
		return out
	}
	// Allocation exists from here on: always free it.
	defer s.exec(stun.MethodRefresh, lifetime(0))

	_, d, err = s.exec(stun.MethodCreatePermission, xorAddr(stun.AttrXORPeerAddress, peer))
	record(OpCreatePermission, d, err)
	permOK := err == nil

	_, d, err = s.exec(stun.MethodChannelBind, channelNumber(firstChannel), xorAddr(stun.AttrXORPeerAddress, peer))
	record(OpChannelBind, d, err)
	bound := err == nil

	// ChannelBind installs the permission too, so either one lets the server
	// relay a Send indication.
	if lt.Cfg.ChannelData && bound {
		lt.sendAndVerify(s.conn, ln, size, OpChannelData, OpPeerChannelData, record,
			func(p []byte) ([]byte, error) { return channelData(firstChannel, p), nil })
	}
	if lt.Cfg.SendIndication && (permOK || bound) {
		lt.sendAndVerify(s.conn, ln, size, OpSendIndication, OpPeerSendIndication, record,
			func(p []byte) ([]byte, error) { return sendIndication(peer, p) })
	}

	return out
}

// sendAndVerify sends one freshly randomised payload framed by frame and
// records the send. With a peer listener it then waits for that exact payload
// to arrive and records the outcome under recvOp; its latency runs from just
// before the send to the arrival at the peer.
func (lt LegitTurn) sendAndVerify(c *conn, ln *peerListener, size int, sendOp, recvOp string,
	record func(string, time.Duration, error), frame func([]byte) ([]byte, error)) {
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	datagram, err := frame(payload)
	if err != nil {
		record(sendOp, 0, err)
		return
	}

	var exp *expectation
	if ln != nil {
		exp = ln.expect(payload)
	}
	start := time.Now()
	err = c.send(datagram)
	record(sendOp, time.Since(start), err)
	if exp == nil {
		return
	}
	if err != nil {
		exp.cancel()
		return
	}
	at, err := exp.wait(lt.Cfg.Timeout)
	record(recvOp, at.Sub(start), err)
}

// session holds the per-allocation authentication state.
type session struct {
	conn          *conn
	username      string
	password      string
	realm, nonce  string
	integrity     stun.MessageIntegrity
	authenticated bool
}

// learn stores REALM and NONCE from a 401/438 response and derives the
// long-term key.
func (s *session) learn(m *stun.Message) error {
	var realm stun.Realm
	var nonce stun.Nonce
	if err := realm.GetFrom(m); err != nil {
		return fmt.Errorf("challenge without REALM: %w", err)
	}
	if err := nonce.GetFrom(m); err != nil {
		return fmt.Errorf("challenge without NONCE: %w", err)
	}
	s.realm, s.nonce = realm.String(), nonce.String()
	s.integrity = stun.NewLongTermIntegrity(s.username, s.realm, s.password)
	s.authenticated = true
	return nil
}

// exec sends one request (authenticated once a challenge has been learned)
// and returns the response and the elapsed time. A 438 Stale Nonce response
// is retried once with the fresh nonce; the retry counts toward the elapsed
// time.
func (s *session) exec(method stun.Method, attrs ...stun.Setter) (*stun.Message, time.Duration, error) {
	start := time.Now()
	for attempt := 0; ; attempt++ {
		setters := make([]stun.Setter, 0, len(attrs)+6)
		setters = append(setters, stun.TransactionID, stun.NewType(method, stun.ClassRequest))
		setters = append(setters, attrs...)
		if s.authenticated {
			setters = append(setters,
				stun.NewUsername(s.username), stun.NewRealm(s.realm), stun.NewNonce(s.nonce), s.integrity)
		}
		req, err := stun.Build(setters...)
		if err != nil {
			return nil, time.Since(start), fmt.Errorf("building %s request: %w", method, err)
		}

		res, err := s.conn.do(req)
		var er *ErrorResponse
		if attempt == 0 && s.authenticated && errors.As(err, &er) && er.Code == codeStaleNonce {
			if lerr := s.learn(er.Msg); lerr == nil {
				continue
			}
		}
		return res, time.Since(start), err
	}
}
