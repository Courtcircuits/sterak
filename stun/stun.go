package stun

import (
	"slices"
	"sync"

	"github.com/Courtcircuits/sterak/capture"
	"github.com/Courtcircuits/sterak/config"
)

type Result struct {
	Time int64
	Err  error
}

func runSTUNRequests(cfg config.Config, cap *capture.Capture) ([]Result, error) {
	lg := LegitStun{
		Cfg: cfg,
		Capture: cap,
	}

	return lg.Run()
}

func runMalformedSTUNRequests(cfg config.Config, cap *capture.Capture) ([]Result, error) {
	lg := MalformedStun{
		Cfg: cfg,
		Capture: cap,
	}

	return lg.Run()
}

func RunSingleTests(cfg config.Config, cap *capture.Capture, results_chan chan Result, err_chan chan error) {
	if slices.Contains(cfg.Scenarios, "legit") {
		results_legit, err := runSTUNRequests(cfg, cap)
		if err != nil {
			err_chan <- err
		}
		for  _, res := range results_legit {
			results_chan <- res
		}
	}

	if slices.Contains(cfg.Scenarios, "malicious") {
		results_mf, err := runMalformedSTUNRequests(cfg, cap)
		if err != nil {
			err_chan <- err
		}
		for  _, res := range results_mf {
			results_chan <- res
		}
	}
}

func RunStunTests(cfg config.Config, cap *capture.Capture) ([]Result, error) {
	var wg sync.WaitGroup
	var results []Result = []Result{}
	err_chan := make(chan error)
	res_chan := make(chan Result)
	for i:=0; i<cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RunSingleTests(cfg, cap, res_chan, err_chan)
		}()
	}

	go func() {
		wg.Wait()
		close(err_chan)
		close(res_chan)
	}()

	for err_chan != nil || res_chan != nil {
		select {
		case r, ok := <- res_chan:
			if !ok {
				res_chan = nil
				continue
			}
			results = append(results, r)
		case e, ok := <- err_chan:
			if !ok {
				err_chan = nil
				continue
			}
			return nil, e
		}
	}

	return results, nil
}
