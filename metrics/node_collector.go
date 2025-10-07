package metrics

import (
	"exporter-prometheus/proto/gen"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// metrics structure for Prometheus
var (
	nodeCpuUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_cpu_usage_percent",
			Help: "CPU usage percent on node",
		},
		[]string{
			"hostname", "os", "platform", "platform_family",
			"platform_version", "kernel_version", "kernel_arch",
			"host_id",
		},
	)

	nodeMemUsed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_memory_used_bytes",
			Help: "Memory used by the node in bytes",
		},
		[]string{"hostname"},
	)

	nodeMemTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_memory_total_bytes",
			Help: "Memory total in the node in bytes",
		},
		[]string{"hostname"},
	)

	nodeMemUsedPerc = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_memory_used_perc",
			Help: "Memory used percent",
		},
		[]string{"hostname"},
	)

	nodeMemFree = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_memory_available_bytes",
			Help: "Memory free in the node in bytes",
		},
		[]string{"hostname"},
	)

	uptimeGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_uptime_seconds",
			Help: "Seconds since node start",
		},
		[]string{"hostname"},
	)

	nodeProcs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_total_procs",
			Help: "Node total processes",
		},
		[]string{"hostname"},
	)

	totalPodInNode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_total_pod",
			Help: "Total number of pods running on this node",
		},
		[]string{"hostname"},
	)

	nodeCpuInfos = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_single_cpu_usage",
			Help: "Node single CPU details",
		},
		[]string{"hostname", "cpu_id", "cpu_model", "physical_cores", "vendor", "physical_id"},
	)

	nodeCpuClockSpeed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_clock_cpu_speed",
			Help: "Node clock speed in mHZ",
		},
		[]string{"hostname", "cpu_id", "cpu_model", "physical_cores", "vendor", "physical_id"},
	)

	processesMemInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "processes_mem_info",
			Help: "Process memory info",
		},
		[]string{"hostname", "pid", "name"},
	)

	nodeNetTotalByteSent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_byte_sent_total",
			Help: "Total number of bytes sent by this node",
		},
		[]string{"hostname"},
	)

	nodeNetTotalByteReceived = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_byte_received_total",
			Help: "Total number of bytes received by this node",
		},
		[]string{"hostname"},
	)

	nodeNetTotalPacketSent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_total_packet_sent",
			Help: "Total number of packets sent by this node",
		},
		[]string{"hostname"},
	)

	nodeNetTotalPacketReceived = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_total_packet_received",
			Help: "Total number of packets received by this node",
		},
		[]string{"hostname"},
	)

	nodeNetTotalInboundPacketErrors = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_total_inbound_packet_error",
			Help: "Number of inbound packet errors",
		},
		[]string{"hostname"},
	)

	nodeNetTotalOutboundPacketErrors = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_total_outbound_packet_error",
			Help: "Number of outbound packet errors",
		},
		[]string{"hostname"},
	)

	nodeNetTotalInboundPacketDropped = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_total_inbound_packet_dropped",
			Help: "Number of inbound packet dropped",
		},
		[]string{"hostname"},
	)

	nodeNetTotalOutboundPacketDropped = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_total_outbound_packet_dropped",
			Help: "Number of outbound packet dropped",
		},
		[]string{"hostname"},
	)

	nodeNetTotalOutboundFifoBufferError = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_total_outbound_fifo_buffer_error",
			Help: "Number of outbound fifo buffer errors",
		},
		[]string{"hostname"},
	)

	nodeNetTotalInboundFifoBufferError = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_total_inbound_fifo_buffer_error",
			Help: "Number of inbound fifo buffer errors",
		},
		[]string{"hostname"},
	)

	nodeNetInterfaces = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_net_interfaces",
			Help: "Node network interfaces",
		},
		[]string{"hostname", "index", "mtu", "name", "hardwareAddr", "flags", "addresses"},
	)

	nodeDiskTotalCapacity = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_disk_capacity_total_bytes",
			Help: "Node disk capacity in bytes",
		},
		[]string{"hostname", "device", "mountpoint", "fstype"},
	)

	nodeDiskUsed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_disk_used_bytes",
			Help: "Node disk used in bytes",
		},
		[]string{"hostname", "device", "mountpoint", "fstype"},
	)

	nodeDiskFree = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_disk_free_bytes",
			Help: "Node disk free in bytes",
		},
		[]string{"hostname", "device", "mountpoint", "fstype"},
	)

	nodeDiskUsagePercentage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_disk_used_perc",
			Help: "Node disk usage percentage",
		},
		[]string{"hostname", "device", "mountpoint", "fstype"},
	)

	//cumulative, across all disks
	nodeDiskTotalReadBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_disk_read_bytes_total",
			Help: "Total bytes read from all disks.",
		},
		[]string{"hostname"},
	)

	//cumulative, across all disks
	nodeDiskTotalWriteBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_disk_write_bytes_total",
			Help: "Total bytes written to all disks.",
		},
		[]string{"hostname"},
	)

	//cumulative, across all disks
	nodeDiskTotalReadOps = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_disk_read_ops_total",
			Help: "Total read operations across all disks.",
		},
		[]string{"hostname"},
	)

	//cumulative, across all disks
	nodeDiskTotalWriteOps = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_disk_write_ops_total",
			Help: "Total write operations across all disks.",
		},
		[]string{"hostname"},
	)

	nodeIOPsiTotalStallMillis = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_io_psi_stall_millis_total",
			Help: "Cumulative time (in microseconds) that tasks have been stalled due to resource pressure since system boot",
		},
		[]string{"hostname"},
	)

	nodeIOPsiRollingStallMillis10Seconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_io_psi_stall_millis_10_seconds",
			Help: "Rolling average of stall time over the last 10 seconds, expressed as a percentage (0.0–100.0)",
		},
		[]string{"hostname"},
	)
	nodeIOPsiRollingStallMillis60Seconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_io_psi_stall_millis_60_seconds",
			Help: "Rolling average of stall time over the last 60 seconds, expressed as a percentage (0.0–100.0)",
		},
		[]string{"hostname"},
	)
	nodeIOPsiRollingStallMillis300Seconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_io_psi_stall_millis_300_seconds",
			Help: "Rolling average of stall time over the last 300 seconds, expressed as a percentage (0.0–100.0)",
		},
		[]string{"hostname"},
	)

	nodeCpuPsiTotalStallMillis = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_cpu_psi_stall_millis_total",
			Help: "Cumulative time (in microseconds) that tasks have been stalled due to resource pressure since system boot",
		},
		[]string{"hostname"},
	)

	nodeCpuPsiRollingStallMillis10Seconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_cpu_psi_stall_millis_10_seconds",
			Help: "Rolling average of stall time over the last 10 seconds, expressed as a percentage (0.0–100.0)",
		},
		[]string{"hostname"},
	)

	nodeCpuPsiRollingStallMillis60Seconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_cpu_psi_stall_millis_60_seconds",
			Help: "Rolling average of stall time over the last 60 seconds, expressed as a percentage (0.0–100.0)",
		},
		[]string{"hostname"},
	)

	nodeCpuPsiRollingStallMillis300Seconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_cpu_psi_stall_millis_300_seconds",
			Help: "Rolling average of stall time over the last 300 seconds, expressed as a percentage (0.0–100.0)",
		},
		[]string{"hostname"},
	)

	nodeMemPsiTotalStallMillis = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_mem_psi_stall_millis_total",
			Help: "Cumulative time (in microseconds) that tasks have been stalled due to resource pressure since system boot",
		},
		[]string{"hostname"},
	)

	nodeMemPsiRollingStallMillis10Seconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_mem_psi_stall_millis_10_seconds",
			Help: "Rolling average of stall time over the last 10 seconds, expressed as a percentage (0.0–100.0)",
		},
		[]string{"hostname"},
	)
	nodeMemPsiRollingStallMillis60Seconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_mem_psi_stall_millis_60_seconds",
			Help: "Rolling average of stall time over the last 60 seconds, expressed as a percentage (0.0–100.0)",
		},
		[]string{"hostname"},
	)
	nodeMemPsiRollingStallMillis300Seconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_mem_psi_stall_millis_300_seconds",
			Help: "Rolling average of stall time over the last 300 seconds, expressed as a percentage (0.0–100.0)",
		},
		[]string{"hostname"},
	)
)

// Register selected metrics at application startup. This is invoked automatically before the main function.
func init() {
	/*NODE INFRASTRUCTURE METRICS*/
	prometheus.MustRegister(nodeCpuUsage)
	prometheus.MustRegister(nodeMemUsed)
	prometheus.MustRegister(nodeMemTotal)
	prometheus.MustRegister(nodeMemFree)
	prometheus.MustRegister(nodeMemUsedPerc)
	prometheus.MustRegister(uptimeGauge)
	prometheus.MustRegister(nodeProcs)
	prometheus.MustRegister(nodeCpuInfos)
	prometheus.MustRegister(nodeCpuClockSpeed)
	prometheus.MustRegister(totalPodInNode)
	prometheus.MustRegister(processesMemInfo)

	/*NODE NETWORK METRICS*/
	prometheus.MustRegister(nodeNetTotalByteSent)
	prometheus.MustRegister(nodeNetTotalByteReceived)
	prometheus.MustRegister(nodeNetTotalPacketSent)
	prometheus.MustRegister(nodeNetTotalPacketReceived)
	prometheus.MustRegister(nodeNetTotalInboundPacketErrors)
	prometheus.MustRegister(nodeNetTotalOutboundPacketErrors)
	prometheus.MustRegister(nodeNetTotalInboundPacketDropped)
	prometheus.MustRegister(nodeNetTotalOutboundPacketDropped)
	prometheus.MustRegister(nodeNetTotalInboundFifoBufferError)
	prometheus.MustRegister(nodeNetTotalOutboundFifoBufferError)
	prometheus.MustRegister(nodeNetInterfaces)

	/*NODE DISK METRICS*/
	prometheus.MustRegister(nodeDiskTotalCapacity)
	prometheus.MustRegister(nodeDiskUsed)
	prometheus.MustRegister(nodeDiskFree)
	prometheus.MustRegister(nodeDiskUsagePercentage)
	prometheus.MustRegister(nodeDiskTotalReadBytes)
	prometheus.MustRegister(nodeDiskTotalWriteBytes)
	prometheus.MustRegister(nodeDiskTotalReadOps)
	prometheus.MustRegister(nodeDiskTotalWriteOps)

	/*PSI*/
	prometheus.MustRegister(nodeIOPsiTotalStallMillis)
	prometheus.MustRegister(nodeIOPsiRollingStallMillis10Seconds)
	prometheus.MustRegister(nodeIOPsiRollingStallMillis60Seconds)
	prometheus.MustRegister(nodeIOPsiRollingStallMillis300Seconds)
	prometheus.MustRegister(nodeCpuPsiTotalStallMillis)
	prometheus.MustRegister(nodeCpuPsiRollingStallMillis10Seconds)
	prometheus.MustRegister(nodeCpuPsiRollingStallMillis60Seconds)
	prometheus.MustRegister(nodeCpuPsiRollingStallMillis300Seconds)
	prometheus.MustRegister(nodeMemPsiTotalStallMillis)
	prometheus.MustRegister(nodeMemPsiRollingStallMillis10Seconds)
	prometheus.MustRegister(nodeMemPsiRollingStallMillis60Seconds)
	prometheus.MustRegister(nodeMemPsiRollingStallMillis300Seconds)
}

// UpdateNodeMetrics update node metrics periodically
func UpdateNodeMetrics(node *gen.NodeMetrics) {
	if node == nil {
		return
	}
	hostname := node.GetHostname()

	nodeCpuUsage.With(prometheus.Labels{
		"hostname":         node.GetHostname(),
		"os":               node.GetOs(),
		"platform":         node.GetPlatform(),
		"platform_family":  node.GetPlatformFamily(),
		"platform_version": node.GetPlatformVersion(),
		"kernel_version":   node.GetKernelVersion(),
		"kernel_arch":      node.GetKernelArch(),
		"host_id":          node.GetHostId(),
	}).Set(node.GetTotalCpuPercentage())

	for _, cpuInfo := range node.GetCpuInfos() {
		nodeCpuInfos.With(prometheus.Labels{
			"hostname":       node.GetHostname(),
			"cpu_id":         cpuInfo.GetCoreId(),
			"cpu_model":      cpuInfo.GetModel(),
			"physical_cores": fmt.Sprintf("%d", cpuInfo.GetCores()),
			"vendor":         cpuInfo.GetVendorId(),
			"physical_id":    cpuInfo.GetPhysicalId(),
		}).Set(cpuInfo.GetUsage())

		nodeCpuClockSpeed.With(prometheus.Labels{
			"hostname":       node.GetHostname(),
			"cpu_id":         cpuInfo.GetCoreId(),
			"cpu_model":      cpuInfo.GetModel(),
			"physical_cores": fmt.Sprintf("%d", cpuInfo.GetCores()),
			"vendor":         cpuInfo.GetVendorId(),
			"physical_id":    cpuInfo.GetPhysicalId(),
		}).Set(float64(cpuInfo.GetMhz()))
	}

	for _, networkInterface := range node.GetNetworkInterfaces() {
		nodeNetInterfaces.With(prometheus.Labels{
			"hostname":     node.GetHostname(),
			"index":        fmt.Sprintf("%d", networkInterface.GetIndex()),
			"mtu":          fmt.Sprintf("%d", networkInterface.GetMtu()),
			"name":         networkInterface.GetName(),
			"hardwareAddr": networkInterface.GetHardwareAddr(),
			"flags":        strings.Join(networkInterface.GetFlags(), ","),
			"addresses":    strings.Join(networkInterface.GetAddrs(), ","),
		}).Set(1)
	}

	//keeps an in-memory map with the current processes scraped
	currentProcesses := make(map[string]struct{})

	for _, processMemInfo := range node.GetProcessesMemInfo() {
		pid := fmt.Sprintf("%d", processMemInfo.GetPid())
		name := processMemInfo.GetName()

		labels := prometheus.Labels{
			"hostname": hostname,
			"pid":      pid,
			"name":     name,
		}

		processesMemInfo.With(labels).Set(float64(processMemInfo.GetMemory()))

		key := fmt.Sprintf("%s|%s|%s", hostname, pid, name)
		currentProcesses[key] = struct{}{}
	}

	metricsChan := make(chan prometheus.Metric, 100)
	go func() {
		processesMemInfo.Collect(metricsChan)
		close(metricsChan)
	}()

	for m := range metricsChan {
		dtoMetric := &dto.Metric{}
		if err := m.Write(dtoMetric); err != nil {
			continue
		}

		var pid, name, hn string
		for _, label := range dtoMetric.GetLabel() {
			switch label.GetName() {
			case "hostname":
				hn = label.GetValue()
			case "pid":
				pid = label.GetValue()
			case "name":
				name = label.GetValue()
			}
		}

		if hn != hostname {
			continue
		}

		key := fmt.Sprintf("%s|%s|%s", hn, pid, name)
		if _, ok := currentProcesses[key]; !ok {
			processesMemInfo.Delete(prometheus.Labels{
				"hostname": hn,
				"pid":      pid,
				"name":     name,
			})
		}
	}

	nodeMemUsed.WithLabelValues(hostname).Set(float64(node.GetUsedMemory()))
	nodeMemTotal.WithLabelValues(hostname).Set(float64(node.GetTotalMemory()))
	nodeMemFree.WithLabelValues(hostname).Set(float64(node.GetAvailableMemory()))
	nodeMemUsedPerc.WithLabelValues(hostname).Set(node.GetMemoryUsedPerc())
	uptimeGauge.WithLabelValues(hostname).Set(float64(node.GetUptime()))
	nodeProcs.WithLabelValues(hostname).Set(float64(node.GetProcs()))

	/*NODE NETWORK METRICS*/
	nodeNetTotalByteSent.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalBytesSent()))
	nodeNetTotalByteReceived.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalBytesReceived()))
	nodeNetTotalPacketSent.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalPacketsSent()))
	nodeNetTotalPacketReceived.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalPacketsReceived()))

	nodeNetTotalInboundPacketErrors.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalErrIn()))
	nodeNetTotalInboundPacketDropped.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalDropIn()))
	nodeNetTotalInboundFifoBufferError.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalFifoErrIn()))

	nodeNetTotalOutboundPacketErrors.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalErrOut()))
	nodeNetTotalOutboundPacketDropped.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalDropOut()))
	nodeNetTotalOutboundFifoBufferError.WithLabelValues(hostname).Set(float64(node.GetNetUsage().GetTotalFifoErrOut()))

	/*NODE DISK METRICS*/
	for _, diskUsage := range node.GetDiskUsages() {
		nodeDiskTotalCapacity.WithLabelValues(hostname, diskUsage.GetDevice(), diskUsage.GetMountpoint(), diskUsage.GetFstype()).Set(float64(diskUsage.GetTotal()))
		nodeDiskUsed.WithLabelValues(hostname, diskUsage.GetDevice(), diskUsage.GetMountpoint(), diskUsage.GetFstype()).Set(float64(diskUsage.GetUsed()))
		nodeDiskFree.WithLabelValues(hostname, diskUsage.GetDevice(), diskUsage.GetMountpoint(), diskUsage.GetFstype()).Set(float64(diskUsage.GetFree()))
		nodeDiskUsagePercentage.WithLabelValues(hostname, diskUsage.GetDevice(), diskUsage.GetMountpoint(), diskUsage.GetFstype()).Set(diskUsage.GetUsedPercent())
	}

	nodeDiskTotalReadBytes.WithLabelValues(hostname).Set(float64(node.GetDiskIoSummary().GetTotalReadBytes()))
	nodeDiskTotalWriteBytes.WithLabelValues(hostname).Set(float64(node.GetDiskIoSummary().GetTotalWriteBytes()))
	nodeDiskTotalReadOps.WithLabelValues(hostname).Set(float64(node.GetDiskIoSummary().GetTotalReadOps()))
	nodeDiskTotalWriteOps.WithLabelValues(hostname).Set(float64(node.GetDiskIoSummary().GetTotalWriteOps()))

	/*PSI*/
	nodeIOPsiTotalStallMillis.WithLabelValues(hostname).Set(float64(node.GetPsiIoMetrics().GetFull().GetTotal().GetValue()))
	nodeIOPsiRollingStallMillis10Seconds.WithLabelValues(hostname).Set(node.GetPsiIoMetrics().GetFull().GetAvg10().GetValue())
	nodeIOPsiRollingStallMillis60Seconds.WithLabelValues(hostname).Set(node.GetPsiIoMetrics().GetFull().GetAvg60().GetValue())
	nodeIOPsiRollingStallMillis300Seconds.WithLabelValues(hostname).Set(node.GetPsiIoMetrics().GetFull().GetAvg300().GetValue())

	nodeCpuPsiTotalStallMillis.WithLabelValues(hostname).Set(float64(node.GetPsiCpuMetrics().GetFull().GetTotal().GetValue()))
	nodeCpuPsiRollingStallMillis10Seconds.WithLabelValues(hostname).Set(node.GetPsiCpuMetrics().GetFull().GetAvg10().GetValue())
	nodeCpuPsiRollingStallMillis60Seconds.WithLabelValues(hostname).Set(node.GetPsiCpuMetrics().GetFull().GetAvg60().GetValue())
	nodeCpuPsiRollingStallMillis300Seconds.WithLabelValues(hostname).Set(node.GetPsiCpuMetrics().GetFull().GetAvg300().GetValue())

	nodeMemPsiTotalStallMillis.WithLabelValues(hostname).Set(float64(node.GetPsiMemoryMetrics().GetFull().GetTotal().GetValue()))
	nodeMemPsiRollingStallMillis10Seconds.WithLabelValues(hostname).Set(node.GetPsiMemoryMetrics().GetFull().GetAvg10().GetValue())
	nodeMemPsiRollingStallMillis60Seconds.WithLabelValues(hostname).Set(node.GetPsiMemoryMetrics().GetFull().GetAvg60().GetValue())
	nodeMemPsiRollingStallMillis300Seconds.WithLabelValues(hostname).Set(node.GetPsiMemoryMetrics().GetFull().GetAvg300().GetValue())

}
