package main

import (
	"flag"
	"time"
)

type Config struct {
	stunHost  string
	runCount  int
	timeout   time.Duration
	scenarios []string
	pcap      bool
	capture   *Capture // non-nil when -pcap is set; nil Capture records nothing
}

func parseFlags() Config {
	stunHost := flag.String("host", "stun.cloudflare.com:3478", "STUN server hostname")
	runCount := flag.Int("runs", 10, "Number of times to run the STUN request")
	timeout := flag.Duration("timeout", 3*time.Second, "Timeout for each STUN request")
	scenario := flag.String("scenario", "both", "Which scenario to run (legit/malicious/both)")
	pcap := flag.Bool("pcap", false, "Captures STUN traffic and saves it in a file")
	flag.Parse()

	var scenarios []string = []string{}

	switch *scenario {
	case "both":
		scenarios = []string{
			"legit",
			"malicious",
		}
	case "legit":
		scenarios = []string{
			"legit",
		}
	case "malicious":
		scenarios = []string{
			"malicious",
		}
	}


	return Config{
		stunHost:  *stunHost,
		runCount:  *runCount,
		timeout:   *timeout,
		pcap:      *pcap,
		scenarios: scenarios,
	}
}
