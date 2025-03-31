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

type HTTPSOnlyServiceAnalyzer struct{}

func (analyzer HTTPSOnlyServiceAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	kind := "Service"
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

	serviceList, err := a.Client.GetClient().CoreV1().Services(a.Namespace).List(a.Context, metav1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, service := range serviceList.Items {
		var failures []common.Failure

		for _, port := range service.Spec.Ports {
			if port.Port == 80 || strings.Contains(strings.ToLower(port.Name), "http") {
				doc := apiDoc.GetApiDocV2("spec.ports")
				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("Service %s is accessible over HTTP on port %d", service.Name, port.Port),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{Unmasked: service.Namespace, Masked: util.MaskString(service.Namespace)},
						{Unmasked: service.Name, Masked: util.MaskString(service.Name)},
					},
				})
			}
		}

		if len(failures) > 0 {
			preAnalysis[fmt.Sprintf("%s/%s", service.Namespace, service.Name)] = common.PreAnalysis{
				FailureDetails: failures,
			}
			AnalyzerErrorsMetric.WithLabelValues(kind, service.Name, service.Namespace).Set(float64(len(failures)))
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
