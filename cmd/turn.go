package cmd

import (
	"fmt"
	"sort"

	"github.com/Courtcircuits/sterak/report"
	"github.com/Courtcircuits/sterak/stun"
	"github.com/Courtcircuits/sterak/turn"
	"github.com/spf13/cobra"
)

func init() {
	f := turnCmd.Flags()
	f.String("username", "", "TURN long-term credential username")
	f.String("password", "", "TURN long-term credential password")
	f.String("peer", "", "Peer address (ip:port) for CreatePermission/ChannelBind (default 203.0.113.5:4000)")
	f.Bool("channel-data", false, "Send a ChannelData message to the peer through the bound channel")
	f.Bool("send-indication", false, "Send a Send indication to the peer")
	f.Int("data-size", 0, "ChannelData / Send indication payload size in bytes (default 64)")
	f.String("peer-listen", "", "Act as the peer: bind this UDP ip:port and verify every sent payload arrives intact (--peer defaults to this address)")
	RootCmd.AddCommand(turnCmd)
}

var turnCmd = &cobra.Command{
	Use:   "turn",
	Short: "TURN mode",
	Long:  "Sends Allocate, CreatePermission and ChannelBind requests to a TURN server over UDP, optionally followed by ChannelData",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, cap, err := configFromFlags(cmd)
		if err != nil {
			return err
		}
		defer cap.Close()

		// Explicit flags override the config file.
		flags := cmd.Flags()
		if flags.Changed("username") {
			cfg.Username, _ = flags.GetString("username")
		}
		if flags.Changed("password") {
			cfg.Password, _ = flags.GetString("password")
		}
		if flags.Changed("peer") {
			cfg.Peer, _ = flags.GetString("peer")
		}
		if flags.Changed("channel-data") {
			cfg.ChannelData, _ = flags.GetBool("channel-data")
		}
		if flags.Changed("data-size") {
			cfg.DataSize, _ = flags.GetInt("data-size")
		}
		if flags.Changed("send-indication") {
			cfg.SendIndication, _ = flags.GetBool("send-indication")
		}
		if flags.Changed("peer-listen") {
			cfg.PeerListen, _ = flags.GetString("peer-listen")
		}

		results, err := turn.RunTurnTests(cfg, cap)
		if err != nil {
			return err
		}

		for _, op := range turn.Operations {
			var group []stun.Result
			errCounts := map[string]int{}
			for _, r := range results {
				if r.Method != op {
					continue
				}
				group = append(group, stun.Result{Time: r.Time, Err: r.Err})
				if r.Err != nil {
					errCounts[r.Err.Error()]++
				}
			}
			if len(group) == 0 {
				continue
			}
			fmt.Printf("\n=== %s ===\n", op)
			report.PrintResults(group)
			printErrorCounts(errCounts)
		}
		return nil
	},
}

func printErrorCounts(counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	msgs := make([]string, 0, len(counts))
	for m := range counts {
		msgs = append(msgs, m)
	}
	sort.Slice(msgs, func(i, j int) bool { return counts[msgs[i]] > counts[msgs[j]] })
	fmt.Println("\nErrors:")
	for _, m := range msgs {
		fmt.Printf("  %5d  %s\n", counts[m], m)
	}
}
