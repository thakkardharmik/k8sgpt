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

type HardcodedCredentialsAnalyzer struct{}

var credentialEnvPatterns = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"api-key", "access_key", "accesskey", "access-key",
	"private_key", "privatekey", "private-key",
	"credential", "auth_token", "auth-token",
}

func (analyzer HardcodedCredentialsAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
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
			for _, env := range container.Env {
				if env.ValueFrom != nil || env.Value == "" {
					continue
				}

				lowerName := strings.ToLower(env.Name)
				for _, pattern := range credentialEnvPatterns {
					if strings.Contains(lowerName, pattern) {
						doc := apiDoc.GetApiDocV2("spec.containers[*].env")
						failures = append(failures, common.Failure{
							Text:          fmt.Sprintf("Container %s in Pod %s has hardcoded credential in env var '%s' (should use secretKeyRef)", container.Name, pod.Name, env.Name),
							KubernetesDoc: doc,
							Sensitive: []common.Sensitive{
								{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
								{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
								{Unmasked: env.Name, Masked: util.MaskString(env.Name)},
								{Unmasked: env.Value, Masked: util.MaskString(env.Value)},
							},
						})
						break
					}
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
