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
	pf.Int("concurrency", 1, "Number of concurrent connections to open")
	pf.String("scenario", "both", "Which scenario to execute: legit, malicious or both")
	pf.Duration("timeout", 2*time.Second, "Time to wait for each response")
	pf.Duration("rate", 0*time.Second, "Time to wait between each request")
	pf.String("config", "", "Config location")
}

var RootCmd = &cobra.Command{
	Use:   "sterak",
	Short: "Differential testing for WebRTC",
	Long:  "Differential testing for WebRTC",
}

// configFromFlags builds a Config from the root persistent flags. When --pcap
// is set it opens a capture file; the caller MUST Close cfg.Capture (nil-safe).
func configFromFlags(cmd *cobra.Command) (config.Config, *capture.Capture, error) {
	var cfg config.Config
	flags := cmd.Flags()

	host, err := flags.GetString("host")
	if err != nil {
		return cfg, nil, err
	}
	runs, err := flags.GetInt("runs")
	if err != nil {
		return cfg, nil, err
	}
	if runs < 1 {
		return cfg, nil, fmt.Errorf("--runs must be at least 1, got %d", runs)
	}
	timeout, err := flags.GetDuration("timeout")
	if err != nil {
		return cfg, nil, err
	}
	rate, err := flags.GetDuration("rate")
	if err != nil {
		return cfg, nil, err
	}
	if timeout <= 0 {
		return cfg, nil, fmt.Errorf("--timeout must be positive, got %s", timeout)
	}
	scenario, err := flags.GetString("scenario")
	if err != nil {
		return cfg, nil, err
	}
	var scenarios []string
	switch scenario {
	case "legit", "malicious":
		scenarios = []string{scenario}
	case "both":
		scenarios = []string{"legit", "malicious"}
	default:
		return cfg, nil, fmt.Errorf("unknown --scenario %q (want legit, malicious or both)", scenario)
	}
	pcap, err := flags.GetBool("pcap")
	if err != nil {
		return cfg, nil, err
	}

	concurrency, err := flags.GetInt("concurrency")
	if err != nil {
		return cfg, nil, err
	}

	cfg = config.Config{
		StunHost:    host,
		RunCount:    runs,
		Timeout:     timeout,
		Scenarios:   scenarios,
		Concurrency: concurrency,
		Rate:        rate,
	}
	config_location, _ := flags.GetString("config")

	if config_location != "" {
		cfg, err = config.ReadConfigFile(config_location)
		if err != nil {
			return config.Config{}, nil, err
		}
	}

	var cap *capture.Capture
	if pcap || cfg.Capture {
		cap, err = capture.NewCapture()
		if err != nil {
			return config.Config{}, nil, err
		}
		fmt.Printf("Capturing traffic to %s\n", cap.Path())
	}
	return cfg, cap, nil
}
