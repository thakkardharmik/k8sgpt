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

type TrustedRegistryAnalyzer struct{}

func (analyzer TrustedRegistryAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
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

	// Define a list of trusted registries
	trustedRegistries := []string{
		"gcr.io",
		"quay.io",
		"docker.io/library",
		"registry.k8s.io",
		"ecr.aws",
	}

	podList, err := a.Client.GetClient().CoreV1().Pods(a.Namespace).List(a.Context, metav1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, pod := range podList.Items {
		var failures []common.Failure

		for _, container := range pod.Spec.Containers {
			image := container.Image
			imageParts := strings.Split(image, "/")

			// Assume images without a registry prefix default to "docker.io"
			registry := "docker.io"
			if len(imageParts) > 1 && strings.Contains(imageParts[0], ".") {
				registry = imageParts[0]
			}

			// Check if the registry is in the trusted list
			isTrusted := false
			for _, trusted := range trustedRegistries {
				if strings.HasPrefix(registry, trusted) {
					isTrusted = true
					break
				}
			}

			if !isTrusted {
				doc := apiDoc.GetApiDocV2("spec.containers[*].image")
				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("Container %s in Pod %s is using an untrusted image registry: %s", container.Name, pod.Name, registry),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
						{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
						{Unmasked: container.Name, Masked: util.MaskString(container.Name)},
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
