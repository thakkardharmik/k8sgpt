package analyzer

import (
	"fmt"
	"strings"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type STIGImageAnalyzer struct{}

func (analyzer STIGImageAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
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
			image := container.Image

			if strings.HasSuffix(image, ":latest") || (!strings.Contains(image, ":") && !strings.Contains(image, "@")) {
				doc := apiDoc.GetApiDocV2("spec.containers[*].image")
				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("Container %s in Pod %s uses unpinned image tag (latest or untagged): %s", container.Name, pod.Name, image),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
						{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
						{Unmasked: image, Masked: util.MaskString(image)},
					},
				})
			}

			if !strings.Contains(image, "@sha256:") {
				doc := apiDoc.GetApiDocV2("spec.containers[*].image")
				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("Container %s in Pod %s uses image without digest pinning: %s", container.Name, pod.Name, image),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
						{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
						{Unmasked: image, Masked: util.MaskString(image)},
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
