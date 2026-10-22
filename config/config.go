package config

import (
	"time"

	"github.com/Courtcircuits/sterak/capture"
)

type Config struct {
	StunHost  string
	Capture   *capture.Capture
	RunCount  int
	Timeout   time.Duration
	Scenarios []string
}
