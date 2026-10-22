package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

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
