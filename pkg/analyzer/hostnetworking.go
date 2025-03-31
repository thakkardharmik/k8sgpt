package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type HostNetworkingAnalyzer struct{}

func (analyzer HostNetworkingAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	kind := "Pod"
	apiDoc := kubernetes.K8sApiReference{
		Kind: kind,
		ApiVersion: schema.GroupVersion{
			Group:   "core",
			Version: "v1",
		},
		OpenapiSchema: a.OpenapiSchema,
	}

	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})

	podList, err := a.Client.GetClient().CoreV1().Pods(a.Namespace).List(a.Context, metav1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, pod := range podList.Items {
		var failures []common.Failure

		// Check if host networking is enabled
		if pod.Spec.HostNetwork {
			doc := apiDoc.GetApiDocV2("spec.hostNetwork")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("Pod %s is using host networking, which may expose it to security risks", pod.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
					{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
				},
			})
		}

		// Check if host ports are used
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if port.HostPort != 0 {
					doc := apiDoc.GetApiDocV2("spec.containers.ports.hostPort")
					failures = append(failures, common.Failure{
						Text:          fmt.Sprintf("Pod %s uses host port %d, which may pose security risks", pod.Name, port.HostPort),
						KubernetesDoc: doc,
						Sensitive: []common.Sensitive{
							{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
							{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
						},
					})
				}
			}
		}

		if len(failures) > 0 {
			preAnalysis[fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)] = common.PreAnalysis{
				FailureDetails: failures,
			}
			AnalyzerErrorsMetric.WithLabelValues(kind, pod.Name, pod.Namespace).Set(float64(len(failures)))
		}
	}

	for key, value := range preAnalysis {
		currentAnalysis := common.Result{
			Kind:  kind,
			Name:  key,
			Error: value.FailureDetails,
		}
		a.Results = append(a.Results, currentAnalysis)
	}

	return a.Results, nil
}
