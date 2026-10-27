package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// DefaultSTUNPort is used when the configured host has no port.
const DefaultSTUNPort = "3478"

// DefaultTURNPeer is the peer address used for CreatePermission/ChannelBind
// when none is configured (TEST-NET-3, never routable). Data is only sent to
// it when ChannelData is enabled.
const DefaultTURNPeer = "203.0.113.5:4000"

// DefaultTURNDataSize is the ChannelData payload size when none is configured.
const DefaultTURNDataSize = 64

// HostPort returns StunHost as a dialable "host:port" string. It accepts
// hostnames, IPv4 and IPv6 literals, with or without a port; IPv6 literals may
// be bare ("2001:db8::1") or bracketed ("[2001:db8::1]:3478"). A missing port
// defaults to DefaultSTUNPort.
func (c Config) HostPort() (string, error) {
	s := strings.TrimSpace(c.StunHost)
	if s == "" {
		return "", fmt.Errorf("STUN host is empty")
	}

	if host, port, err := net.SplitHostPort(s); err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("invalid STUN host %q", c.StunHost)
		}
		return net.JoinHostPort(host, port), nil
	}

	// No port: strip optional brackets, then require that anything containing
	// a colon is a valid IPv6 literal.
	host := s
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") {
			return "", fmt.Errorf("invalid STUN host %q", c.StunHost)
		}
		host = host[1 : len(host)-1]
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("invalid STUN host %q: %w", c.StunHost, err)
		}
	}
	if host == "" {
		return "", fmt.Errorf("invalid STUN host %q", c.StunHost)
	}
	return net.JoinHostPort(host, DefaultSTUNPort), nil
}

// duration unmarshals from a Go duration string ("50ms") or a number of
// nanoseconds.
type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch v := v.(type) {
	case string:
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return err
		}
		*d = duration(parsed)
	case float64:
		*d = duration(time.Duration(v))
	default:
		return fmt.Errorf("invalid duration %s", b)
	}
	return nil
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type plain Config
	aux := struct {
		*plain
		Timeout duration `json:"timeout"`
		Rate    duration `json:"rate"`
	}{plain: (*plain)(c)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.Timeout = time.Duration(aux.Timeout)
	c.Rate = time.Duration(aux.Rate)
	return nil
}

func ReadConfigFile(path string) (Config, error) {
	var cfg Config

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config file %q: %w", path, err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	return cfg, nil
}

type Config struct {
	StunHost    string        `json:"host"`
	Capture     bool          `json:"capture"`
	RunCount    int           `json:"run_count"`
	Timeout     time.Duration `json:"timeout"`
	Concurrency int           `json:"concurrency"`
	Scenarios   []string      `json:"scenarios"`
	Rate        time.Duration `json:"rate"`

	// TURN-only settings. Username/Password are the long-term credentials
	// (leave empty for a server that does not require authentication); Peer
	// is the "ip:port" used for CreatePermission/ChannelBind and defaults to
	// DefaultTURNPeer. With ChannelData set, each session also sends one
	// ChannelData message of DataSize bytes (DefaultTURNDataSize if 0) to
	// the peer through the bound channel; SendIndication does the same with
	// a Send indication.
	//
	// PeerListen makes sterak itself the peer: it binds this UDP "ip:port",
	// and every ChannelData / Send indication payload must arrive there
	// unmodified, otherwise the session records an error. Peer defaults to
	// the bound address; set it when the TURN server reaches the listener
	// under a different address (NAT, wildcard bind).
	Username       string `json:"username"`
	Password       string `json:"password"`
	Peer           string `json:"peer"`
	ChannelData    bool   `json:"channel_data"`
	SendIndication bool   `json:"send_indication"`
	DataSize       int    `json:"data_size"`
	PeerListen     string `json:"peer_listen"`
}
