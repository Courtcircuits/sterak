package turn

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/Courtcircuits/sterak/capture"
	"github.com/Courtcircuits/sterak/config"
	"github.com/schollz/progressbar/v3"
)

// MaliciousTurn sprays ChannelData messages at the server without any prior
// Allocate: per RFC 5766 §11.4 the server must silently discard them since no
// channel is bound. Each run uses a fresh UDP socket (fresh 5-tuple) and a
// random channel number in the valid 0x4000-0x4fff range.
type MaliciousTurn struct {
	Cfg     config.Config
	Capture *capture.Capture
}

func (mt MaliciousTurn) Run() ([]Result, error) {
	cfg := mt.Cfg

	hostPort, err := cfg.HostPort()
	if err != nil {
		return nil, err
	}
	server, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve TURN host: %w", err)
	}

	size := cfg.DataSize
	if size == 0 {
		size = config.DefaultTURNDataSize
	}
	if size < 0 || size > maxChannelDataPayload {
		return nil, fmt.Errorf("invalid data size %d (want 1-%d)", size, maxChannelDataPayload)
	}

	workers := max(cfg.Concurrency, 1)
	fmt.Println("Starting malicious TURN sessions...")
	bar := progressbar.Default(int64(cfg.RunCount * workers))

	var (
		mu      sync.Mutex
		results = make([]Result, 0, cfg.RunCount*workers)
		wg      sync.WaitGroup
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range cfg.RunCount {
				res := mt.session(server, size)

				mu.Lock()
				results = append(results, res...)
				mu.Unlock()

				bar.Add(1)
				time.Sleep(cfg.Rate)
			}
		}()
	}
	wg.Wait()

	fmt.Println() // New line after progress bar
	return results, nil
}

// session sends one unauthenticated ChannelData message and records it under
// OpChannelData. ChannelData gets no reply, so the latency is the local send
// time.
func (mt MaliciousTurn) session(server *net.UDPAddr, size int) []Result {
	var out []Result
	record := func(method string, d time.Duration, err error) {
		out = append(out, Result{Method: method, Time: d.Microseconds(), Err: err})
	}

	raw, err := net.DialUDP("udp", nil, server)
	if err != nil {
		record(OpChannelData, 0, fmt.Errorf("failed to dial TURN server: %w", err))
		return out
	}
	defer raw.Close()

	c := newConn(mt.Capture.Wrap(raw), mt.Cfg.Timeout)

	payload := make([]byte, size)
	_, _ = rand.Read(payload)

	channelID := firstChannel
	if n, err := rand.Int(rand.Reader, big.NewInt(0x1000)); err == nil {
		channelID += uint16(n.Int64())
	}

	start := time.Now()
	err = c.send(channelData(channelID, payload))
	record(OpChannelData, time.Since(start), err)
	return out
}
