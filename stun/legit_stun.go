package stun

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Courtcircuits/sterak/capture"
	"github.com/Courtcircuits/sterak/config"
	"github.com/pion/stun"
	"github.com/schollz/progressbar/v3"
)

type LegitStun struct {
	Cfg config.Config
	Capture *capture.Capture
}

func (ls LegitStun) Run() ([]Result, error) {
	cfg := ls.Cfg
	u, err := stun.ParseURI("stun:" + cfg.StunHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse STUN URI: %w", err)
	}

	conn, err := net.Dial("udp", net.JoinHostPort(u.Host, strconv.Itoa(u.Port)))
	if err != nil {
		return nil, fmt.Errorf("failed to dial STUN server: %w", err)
	}

	c, err := stun.NewClient(ls.Capture.Wrap(conn))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create STUN client: %w", err)
	}
	defer c.Close()

	results := make([]Result, cfg.RunCount)

	fmt.Println("Starting STUN requests...")
	bar := progressbar.Default(int64(cfg.RunCount))

	for i := 0; i < cfg.RunCount; i++ {
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
		results[i] = Result{Time: elapsed, Err: err}

		bar.Add(1)
		time.Sleep(cfg.Rate)
	}

	fmt.Println() // New line after progress bar
	return results, nil

}
