package main

import (
	"fmt"
	"time"

	"github.com/pion/stun"
	"github.com/schollz/progressbar/v3"
)

type LegitStun struct {
	Cfg config
}

func (ls LegitStun) Run() ([]result, error) {
	cfg := ls.Cfg
	u, err := stun.ParseURI("stun:" + cfg.stunHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse STUN URI: %w", err)
	}

	c, err := stun.DialURI(u, &stun.DialConfig{})
	if err != nil {
		return nil, fmt.Errorf("failed to dial STUN server: %w", err)
	}
	defer c.Close()

	results := make([]result, cfg.runCount)

	fmt.Println("Starting STUN requests...")
	bar := progressbar.Default(int64(cfg.runCount))

	for i := 0; i < cfg.runCount; i++ {
		message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

		start := time.Now()
		err := c.Do(message, func(res stun.Event) {
			if res.Error != nil {
				return
			}

			var xorAddr stun.XORMappedAddress
			if err := xorAddr.GetFrom(res.Message); err != nil {
				return
			}

			if i == 0 {
				fmt.Printf("\nYour IP is: %s\n", xorAddr.IP)
			}
		})

		elapsed := time.Since(start).Microseconds()
		results[i] = result{time: elapsed, err: err}

		bar.Add(1)
	}

	fmt.Println() // New line after progress bar
	return results, nil

}
