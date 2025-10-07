package cli

import (
	"flag"

	"go.uber.org/zap"
)

type RelayConfig struct {
	RelayAddress string
}

func RegisterRelayFlags(fs *flag.FlagSet) func(logger *zap.Logger) *RelayConfig {
	relayAddress := fs.String("relay-address", "", "Relay address (required)")

	return func(logger *zap.Logger) *RelayConfig {
		if *relayAddress == "" {
			logger.Fatal("Missing required flag: --relay-address")
		}

		return &RelayConfig{
			RelayAddress: *relayAddress,
		}
	}
}
