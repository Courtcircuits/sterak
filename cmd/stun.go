package cmd

import (
	"github.com/Courtcircuits/sterak/report"
	"github.com/Courtcircuits/sterak/stun"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(stunCmd)
}

var stunCmd = &cobra.Command{
	Use:   "stun",
	Short: "STUN mode",
	Long:  "STUN mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, cap, err := configFromFlags(cmd)
		if err != nil {
			return err
		}
		defer cap.Close()

		results, err := stun.RunStunTests(cfg, cap)
		if err != nil {
			return err
		}

		report.PrintResults(results)
		report.PrintASCIIHistogram(results)
		return nil
	},
}
