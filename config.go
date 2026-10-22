package main

import (
	"flag"
	"time"
)

func parseFlags() config {
	stunHost := flag.String("host", "stun.cloudflare.com:3478", "STUN server hostname")
	runCount := flag.Int("runs", 1, "Number of times to run the STUN request")
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout for each STUN request")
	scenario := flag.String("scenario", "both", "Which scenario to run (legit/malicious/both)")
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

	return config{
		stunHost:  *stunHost,
		runCount:  *runCount,
		timeout:   *timeout,
		scenarios: scenarios,
	}
}
