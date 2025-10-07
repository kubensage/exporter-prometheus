package main

import (
	"context"
	"exporter-prometheus/metrics"
	"exporter-prometheus/pkg/cli"
	"exporter-prometheus/proto/gen"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubensage/common/cli"
	"github.com/kubensage/common/grpc"
	"github.com/kubensage/common/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

const appName = "exporter-prometheus"

func main() {
	logCfgFn := gocli.RegisterLogStdFlags(flag.CommandLine)
	agentCfgFn := cli.RegisterRelayFlags(flag.CommandLine)

	flag.Parse()

	logCfg := logCfgFn()
	logger := golog.SetupStdLogger(logCfg)
	exporterCfg := agentCfgFn(logger)

	// Startup info
	logger.Info("starting application", zap.String("app", appName))
	logger.Debug("loaded configuration",
		zap.Any("logCfg", logCfg),
		zap.Any("exporterCfg", exporterCfg))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals (Ctrl+C o SIGTERM)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	}()

	// relay conn
	relayClient, relayConn := SetupRelayConnection(exporterCfg.RelayAddress, logger)
	defer func() {
		if err := relayConn.Close(); err != nil {
			logger.Warn("failed to close relay connection", zap.Error(err))
		}
	}()

	stream, err := relayClient.SubscribeMetrics(ctx, &emptypb.Empty{})
	if err != nil {
		logger.Error("failed to subscribe to metrics stream", zap.Error(err))
		cancel()
		return
	}
	logger.Info("successfully subscribed to metrics stream")

	// Start HTTP server
	startServer(logger, cancel)

	// get metrics
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down metrics receiver")
			return
		default:
			msg, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					logger.Info("stream closed due to context cancellation")
					return
				}
				logger.Warn("stream error, shutting down", zap.Error(err))
				cancel()
				return
			}

			logger.Debug("received metrics",
				zap.String("host", msg.GetNodeMetrics().GetHostname()),
				zap.Int("n_of_pods", len(msg.GetPodMetrics())))

			processMetrics(msg)
		}
	}
}

// start HTTP server function in a separated goroutine
func startServer(logger *zap.Logger, cancel context.CancelFunc) {
	go func() {
		logger.Info("starting HTTP server for Prometheus metrics collection")
		http.Handle("/metrics", promhttp.Handler())
		logger.Debug("prometheus metrics available at http://localhost:8080/metrics")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			logger.Error("HTTP server failed", zap.Error(err))
			cancel()
		}
	}()
}

func processMetrics(msg *gen.Metrics) {
	hostname := msg.GetNodeMetrics().GetHostname()
	metrics.UpdateNodeMetrics(msg.GetNodeMetrics())
	metrics.UpdatePodMetrics(msg.GetPodMetrics(), hostname)
}

func SetupRelayConnection(
	addr string,
	logger *zap.Logger,
) (client gen.MetricsServiceClient, connection *grpc.ClientConn) {
	logger.Debug("connecting to relay GRPC server", zap.String("socket", addr))
	conn := gogrpc.InsecureGrpcConnection(addr, logger)
	logger.Info("connected to relay GRPC server", zap.String("socket", addr))
	return gen.NewMetricsServiceClient(conn), conn
}
