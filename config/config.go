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
}
