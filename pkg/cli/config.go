package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/kubensage/exporter-prometheus/pkg/buildinfo"

	"go.uber.org/zap"
)

type RelayConfig struct {
	RelayAddress string
}

func RegisterRelayFlags(fs *flag.FlagSet) func(logger *zap.Logger) *RelayConfig {
	relayAddress := fs.String("relay-address", "", "Relay address (required)")
	version := fs.Bool("version", false, "Print the current version and exit")

	return func(logger *zap.Logger) *RelayConfig {
		// Handle version flag
		if *version {
			fmt.Printf("%s\n", buildinfo.Version)
			os.Exit(0)
		}

		if *relayAddress == "" {
			logger.Fatal("Missing required flag: --relay-address")
		}

		return &RelayConfig{
			RelayAddress: *relayAddress,
		}
	}
}
