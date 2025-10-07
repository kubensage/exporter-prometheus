module github.com/kubensage/exporter-prometheus

go 1.24.4

// replace github.com/kubensage/common => /home/roman/kubensage/common

require (
	github.com/kubensage/common v0.0.2
	go.uber.org/zap v1.27.0
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.10
)

require go.yaml.in/yaml/v2 v2.4.3 // indirect

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/client_model v0.6.2
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251006185510-65f7160b3a87 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)
