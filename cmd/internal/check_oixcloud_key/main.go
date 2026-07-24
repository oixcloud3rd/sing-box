package main

import (
	"fmt"
	"os"

	"github.com/sagernet/sing-box/cmd/internal/build_shared"
)

func main() {
	_, err := build_shared.OIXCloudLinkerFlag(true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
