package main

import (
	"os"

	"github.com/Courtcircuits/sterak/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
