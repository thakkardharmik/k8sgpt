package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ResourceLimitsAnalyzer struct{}

func (analyzer ResourceLimitsAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
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

		for _, container := range pod.Spec.Containers {
			limits := container.Resources.Limits
			missingCPU := limits.Cpu().IsZero()
			missingMemory := limits.Memory().IsZero()

			if missingCPU || missingMemory {
				doc := apiDoc.GetApiDocV2("spec.containers[*].resources.limits")
				failures = append(failures, common.Failure{
					Text: fmt.Sprintf("Container %s in Pod %s is missing resource limits (CPU: %v, Memory: %v)",
						container.Name, pod.Name, missingCPU, missingMemory),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
						{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
						{Unmasked: container.Name, Masked: util.MaskString(container.Name)},
					},
				})
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
