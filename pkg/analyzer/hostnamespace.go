package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type HostNamespaceAnalyzer struct{}

func (analyzer HostNamespaceAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	kind := "Pod"
	apiDoc := kubernetes.K8sApiReference{
		Kind: kind,
		ApiVersion: schema.GroupVersion{
			Group:   "",
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

		// Check if pod is sharing sensitive host namespaces
		if pod.Spec.HostPID || pod.Spec.HostIPC || pod.Spec.HostNetwork {
			var sharedNamespaces []string
			if pod.Spec.HostPID {
				sharedNamespaces = append(sharedNamespaces, "PID")
			}
			if pod.Spec.HostIPC {
				sharedNamespaces = append(sharedNamespaces, "IPC")
			}
			if pod.Spec.HostNetwork {
				sharedNamespaces = append(sharedNamespaces, "Network")
			}

			doc := apiDoc.GetApiDocV2("spec.hostPID / spec.hostIPC / spec.hostNetwork")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("Pod %s is sharing sensitive host namespaces: %v", pod.Name, sharedNamespaces),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
					{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
				},
			})
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
