// Package turn implements TURN (RFC 5766) traffic scenarios over UDP.
package turn

import (
	"slices"

	"github.com/Courtcircuits/sterak/capture"
	"github.com/Courtcircuits/sterak/config"
)

// RunTurnTests runs the configured TURN scenarios sequentially and returns
// the concatenated results. Each scenario manages its own concurrency.
func RunTurnTests(cfg config.Config, cap *capture.Capture) ([]Result, error) {
	var results []Result
	if slices.Contains(cfg.Scenarios, "legit") {
		res, err := LegitTurn{Cfg: cfg, Capture: cap}.Run()
		if err != nil {
			return nil, err
		}
		results = append(results, res...)
	}
	if slices.Contains(cfg.Scenarios, "malicious") {
		res, err := MaliciousTurn{Cfg: cfg, Capture: cap}.Run()
		if err != nil {
			return nil, err
		}
		results = append(results, res...)
	}
	return results, nil
}
