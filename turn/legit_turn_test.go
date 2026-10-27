package turn

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Courtcircuits/sterak/config"
	pturn "github.com/pion/turn/v3"
)

const (
	testRealm = "sterak.test"
	testUser  = "alice"
	testPass  = "s3cret"
)

// startServer runs a real pion TURN server on a loopback UDP port.
func startServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := pturn.GenerateAuthKey(testUser, testRealm, testPass)
	srv, err := pturn.NewServer(pturn.ServerConfig{
		Realm: testRealm,
		AuthHandler: func(username, realm string, _ net.Addr) ([]byte, bool) {
			if username == testUser {
				return key, true
			}
			return nil, false
		},
		PacketConnConfigs: []pturn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &pturn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return pc.LocalAddr().String()
}

func runLegit(t *testing.T, cfg config.Config) []Result {
	t.Helper()
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.RunCount == 0 {
		cfg.RunCount = 1
	}
	res, err := LegitTurn{Cfg: cfg}.Run()
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func byMethod(rs []Result) map[string][]Result {
	m := map[string][]Result{}
	for _, r := range rs {
		m[r.Method] = append(m[r.Method], r)
	}
	return m
}

func TestLegitSessionAgainstRealServer(t *testing.T) {
	host := startServer(t)
	res := runLegit(t, config.Config{
		StunHost: host, Username: testUser, Password: testPass,
		RunCount: 3, Concurrency: 2,
	})

	got := byMethod(res)
	// The send/peer-receive operations are opt-in, covered below.
	for _, op := range Operations[:4] {
		if len(got[op]) != 6 {
			t.Errorf("%s: want 6 results (3 runs x 2 workers), got %d", op, len(got[op]))
		}
		for _, r := range got[op] {
			if r.Err != nil {
				t.Errorf("%s failed: %v", op, r.Err)
			}
			if r.Time <= 0 {
				t.Errorf("%s: non-positive latency %d", op, r.Time)
			}
		}
	}
}

// An independent raw socket as peer: guards the verifier itself, since the
// built-in listener and the sender share the same payload code.
func TestSendsReachRawPeerWithoutFraming(t *testing.T) {
	host := startServer(t)
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	const size = 200
	res := runLegit(t, config.Config{
		StunHost: host, Username: testUser, Password: testPass,
		Peer: peer.LocalAddr().String(), ChannelData: true, SendIndication: true, DataSize: size,
	})
	got := byMethod(res)
	for _, op := range []string{OpChannelData, OpSendIndication} {
		if len(got[op]) != 1 || got[op][0].Err != nil {
			t.Fatalf("%s: want one successful send, got %+v", op, got[op])
		}
	}

	buf := make([]byte, 65535)
	for i, what := range []string{"ChannelData", "Send indication"} {
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			t.Fatalf("peer received nothing for %s: %v", what, err)
		}
		if n != size {
			t.Errorf("datagram %d (%s): peer got %d bytes, want %d (framing must be stripped)", i, what, n, size)
		}
	}
}

func TestPeerListenVerifiesDelivery(t *testing.T) {
	host := startServer(t)
	res := runLegit(t, config.Config{
		StunHost: host, Username: testUser, Password: testPass,
		PeerListen: "127.0.0.1:0", ChannelData: true, SendIndication: true, DataSize: 300,
		RunCount: 3, Concurrency: 2,
	})
	got := byMethod(res)
	for _, op := range []string{OpChannelData, OpPeerChannelData, OpSendIndication, OpPeerSendIndication} {
		if len(got[op]) != 6 {
			t.Errorf("%s: want 6 results (3 runs x 2 workers), got %d", op, len(got[op]))
		}
		for _, r := range got[op] {
			if r.Err != nil {
				t.Errorf("%s failed: %v", op, r.Err)
			}
			if r.Time <= 0 {
				t.Errorf("%s: non-positive latency %d", op, r.Time)
			}
		}
	}
}

// The relay delivers to a different socket than the one under verification:
// the peer-receive result must fail instead of reporting a send as success.
func TestPeerListenDetectsMissingDelivery(t *testing.T) {
	host := startServer(t)
	elsewhere, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer elsewhere.Close()

	res := runLegit(t, config.Config{
		StunHost: host, Username: testUser, Password: testPass,
		PeerListen: "127.0.0.1:0", Peer: elsewhere.LocalAddr().String(),
		ChannelData: true, SendIndication: true, Timeout: 300 * time.Millisecond,
	})
	got := byMethod(res)
	for _, op := range []string{OpChannelData, OpSendIndication} {
		if len(got[op]) != 1 || got[op][0].Err != nil {
			t.Errorf("%s: the send itself should succeed, got %+v", op, got[op])
		}
	}
	for _, op := range []string{OpPeerChannelData, OpPeerSendIndication} {
		if len(got[op]) != 1 || got[op][0].Err == nil {
			t.Errorf("%s: want one failed receive, got %+v", op, got[op])
		}
	}
}

func TestPeerListenConfigErrors(t *testing.T) {
	cases := map[string]config.Config{
		"nothing sent":          {PeerListen: "127.0.0.1:0"},
		"wildcard without peer": {PeerListen: "0.0.0.0:0", ChannelData: true},
		"oversized indication":  {ChannelData: true, SendIndication: true, DataSize: maxSendIndicationPayload + 1},
	}
	for name, cfg := range cases {
		cfg.StunHost = "127.0.0.1:1"
		if _, err := (LegitTurn{Cfg: cfg}).Run(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestChannelDataOffByDefault(t *testing.T) {
	host := startServer(t)
	res := runLegit(t, config.Config{StunHost: host, Username: testUser, Password: testPass})
	if n := len(byMethod(res)[OpChannelData]); n != 0 {
		t.Errorf("channel-data must be opt-in, got %d results", n)
	}
}

func TestChannelDataInvalidSize(t *testing.T) {
	_, err := LegitTurn{Cfg: config.Config{StunHost: "127.0.0.1:1", ChannelData: true, DataSize: 70000}}.Run()
	if err == nil {
		t.Fatal("want error for oversized payload")
	}
}

func TestWrongPasswordFailsAllocate(t *testing.T) {
	host := startServer(t)
	res := runLegit(t, config.Config{StunHost: host, Username: testUser, Password: "wrong"})

	got := byMethod(res)
	if len(got[OpAllocate]) != 1 || got[OpAllocate][0].Err == nil {
		t.Fatalf("want one failed allocate, got %+v", got[OpAllocate])
	}
	if !strings.Contains(got[OpAllocate][0].Err.Error(), "Allocate error") {
		t.Errorf("want Allocate error response, got %v", got[OpAllocate][0].Err)
	}
	if len(got[OpCreatePermission])+len(got[OpChannelBind]) != 0 {
		t.Error("permission/bind must not be attempted without an allocation")
	}
}

func TestMissingCredentialsReported(t *testing.T) {
	host := startServer(t)
	res := runLegit(t, config.Config{StunHost: host})

	got := byMethod(res)
	if len(got[OpAllocate]) != 1 || got[OpAllocate][0].Err == nil ||
		!strings.Contains(got[OpAllocate][0].Err.Error(), "requires authentication") {
		t.Fatalf("want 'requires authentication' allocate error, got %+v", got[OpAllocate])
	}
}

func TestUnreachableServerTimesOut(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0") // bound, never answers
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	cfg := config.Config{StunHost: pc.LocalAddr().String(), RunCount: 1, Timeout: 100 * time.Millisecond}
	res, err := LegitTurn{Cfg: cfg}.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "no response") {
		t.Fatalf("want single timeout result, got %+v", res)
	}
}
