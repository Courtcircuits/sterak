package cmd

import (
	"fmt"
	"time"

	"github.com/Courtcircuits/sterak/capture"
	"github.com/Courtcircuits/sterak/config"
	"github.com/spf13/cobra"
)

func init() {
	pf := RootCmd.PersistentFlags()
	pf.Bool("pcap", false, "Capture traffic")
	pf.String("host", "stun.cloudflare.com:3478", "Host to execute tests on")
	pf.Int("runs", 10, "Number of requests to send")
	pf.String("scenario", "both", "Which scenario to execute: legit, malicious or both")
	pf.Duration("timeout", 2*time.Second, "Time to wait for each response")
}

var RootCmd = &cobra.Command{
	Use:   "sterak",
	Short: "Differential testing for WebRTC",
	Long:  "Differential testing for WebRTC",
}

// configFromFlags builds a Config from the root persistent flags. When --pcap
// is set it opens a capture file; the caller MUST Close cfg.Capture (nil-safe).
func configFromFlags(cmd *cobra.Command) (config.Config, error) {
	var cfg config.Config
	flags := cmd.Flags()

	host, err := flags.GetString("host")
	if err != nil {
		return cfg, err
	}
	runs, err := flags.GetInt("runs")
	if err != nil {
		return cfg, err
	}
	if runs < 1 {
		return cfg, fmt.Errorf("--runs must be at least 1, got %d", runs)
	}
	timeout, err := flags.GetDuration("timeout")
	if err != nil {
		return cfg, err
	}
	if timeout <= 0 {
		return cfg, fmt.Errorf("--timeout must be positive, got %s", timeout)
	}
	scenario, err := flags.GetString("scenario")
	if err != nil {
		return cfg, err
	}
	var scenarios []string
	switch scenario {
	case "legit", "malicious":
		scenarios = []string{scenario}
	case "both":
		scenarios = []string{"legit", "malicious"}
	default:
		return cfg, fmt.Errorf("unknown --scenario %q (want legit, malicious or both)", scenario)
	}
	pcap, err := flags.GetBool("pcap")
	if err != nil {
		return cfg, err
	}

	cfg = config.Config{
		StunHost:  host,
		RunCount:  runs,
		Timeout:   timeout,
		Scenarios: scenarios,
	}
	if pcap {
		c, err := capture.NewCapture()
		if err != nil {
			return config.Config{}, err
		}
		cfg.Capture = c
		fmt.Printf("Capturing traffic to %s\n", c.Path())
	}
	return cfg, nil
}
