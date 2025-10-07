package metrics

import (
	"fmt"

	"github.com/kubensage/exporter-prometheus/proto/gen"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// metrics structure for Prometheus
var (
	containerCPUUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "container_cpu_usage_nano_cores",
			Help: "CPU usage in nano cores per container",
		},
		[]string{"hostname", "namespace", "pod", "container", "image", "state", "attempt"},
	)

	containerMemUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "container_memory_usage_bytes",
			Help: "Memory usage in bytes per container",
		},
		[]string{"hostname", "namespace", "pod", "container", "image", "state", "attempt"},
	)

	nodePodList = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_pods_list",
			Help: "Pod list related to node",
		},
		[]string{"hostname", "pod", "namespace", "pod_state", "created_at", "pod_id"},
	)

	podContainerList = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "node_container_list",
			Help: "Container list related to pod",
		},
		[]string{"hostname", "namespace", "pod", "container"},
	)
)

// Register selected metrics at application startup. This is invoked automatically before the main function.
func init() {
	prometheus.MustRegister(containerCPUUsage)
	prometheus.MustRegister(containerMemUsage)
	prometheus.MustRegister(nodePodList)
	prometheus.MustRegister(podContainerList)
}

// UpdateContainerMetrics update container metrics periodically. Iterate over Pods to retrieve container information
func UpdatePodMetrics(pods []*gen.PodMetrics, hostname string) {

	//keeps an in-memory map with the current processes scraped
	currentPods := make(map[string]struct{})

	for _, pod := range pods {

		name := pod.GetName()

		labels := prometheus.Labels{
			"hostname":   hostname,
			"pod":        name,
			"namespace":  pod.GetNamespace(),
			"pod_state":  pod.GetState(),
			"created_at": fmt.Sprintf("%d", pod.GetCreatedAt()),
			"pod_id":     pod.GetId(),
		}

		nodePodList.With(labels).Set(1)

		key := fmt.Sprintf("%s|%s|%s|%s|%d|%s", hostname, name, pod.GetNamespace(), pod.GetState(), pod.GetCreatedAt(), pod.GetId())
		currentPods[key] = struct{}{}
	}

	metricsChan := make(chan prometheus.Metric, 100)
	go func() {
		nodePodList.Collect(metricsChan)
		close(metricsChan)
	}()

	for m := range metricsChan {
		dtoMetric := &dto.Metric{}
		if err := m.Write(dtoMetric); err != nil {
			continue
		}

		var source, target, namespace, state, createdAt, podId string
		for _, label := range dtoMetric.GetLabel() {
			switch label.GetName() {
			case "hostname":
				source = label.GetValue()
			case "pod":
				target = label.GetValue()
			case "namespace":
				namespace = label.GetValue()
			case "pod_state":
				state = label.GetValue()
			case "created_at":
				createdAt = label.GetValue()
			case "pod_id":
				podId = label.GetValue()
			}
		}

		if source != hostname {
			continue
		}

		key := fmt.Sprintf("%s|%s|%s|%s|%s|%s", source, target, namespace, state, createdAt, podId)
		if _, ok := currentPods[key]; !ok {
			nodePodList.Delete(prometheus.Labels{
				"hostname":   source,
				"pod":        target,
				"namespace":  namespace,
				"pod_state":  state,
				"created_at": createdAt,
				"pod_id":     podId,
			})
		}
	}

	for _, pod := range pods {
		namespace := pod.GetNamespace()
		podName := pod.GetName()

		for _, container := range pod.ContainerMetrics {
			podContainerList.WithLabelValues(hostname, namespace, podName, container.GetName()).Set(1)

			cName := container.GetName()
			cImage := container.GetImage()
			cState := container.GetState()
			cAttempt := container.GetAttempt()

			cpu := container.GetCpuMetrics().GetUsageNanoCores().GetValue()
			mem := container.GetMemoryMetrics().GetUsageBytes().GetValue()

			containerCPUUsage.WithLabelValues(hostname, namespace, podName, cName, cImage, cState, fmt.Sprintf("%d", cAttempt)).Set(float64(cpu))
			containerMemUsage.WithLabelValues(hostname, namespace, podName, cName, cImage, cState, fmt.Sprintf("%d", cAttempt)).Set(float64(mem))
		}
	}
}
