package stun

import (
	"slices"

	"github.com/Courtcircuits/sterak/config"
)

type Result struct {
	Time int64
	Err  error
}

func runSTUNRequests(cfg config.Config) ([]Result, error) {
	lg := LegitStun{
		Cfg: cfg,
	}

	return lg.Run()
}

func runMalformedSTUNRequests(cfg config.Config) ([]Result, error) {
	lg := MalformedStun{
		Cfg: cfg,
	}

	return lg.Run()
}

func RunStunTests(cfg config.Config) ([]Result, error) {
	var results []Result = []Result{}

	if slices.Contains(cfg.Scenarios, "legit") {
		results_legit, err := runSTUNRequests(cfg)
		if err != nil {
			return results, err
		}
		results = append(results, results_legit...)
	}

	if slices.Contains(cfg.Scenarios, "malicious") {
		results_mf, err := runMalformedSTUNRequests(cfg)
		if err != nil {
			return results, err
		}
		results = append(results, results_mf...)
	}
	return results, nil
}
