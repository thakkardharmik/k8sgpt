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

type TLSMinVersionAnalyzer struct{}

var disallowedProtocols = []string{"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}

func (analyzer TLSMinVersionAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	kind := "Ingress"
	apiDoc := kubernetes.K8sApiReference{
		Kind: kind,
		ApiVersion: schema.GroupVersion{
			Group:   "networking",
			Version: "v1",
		},
		OpenapiSchema: a.OpenapiSchema,
	}

	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})

	list, err := a.Client.GetClient().NetworkingV1().Ingresses(a.Namespace).List(a.Context, metav1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, ing := range list.Items {
		var failures []common.Failure

		if len(ing.Spec.TLS) == 0 {
			doc := apiDoc.GetApiDocV2("spec.tls")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("Ingress %s/%s has no TLS configuration", ing.Namespace, ing.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: ing.Namespace, Masked: util.MaskString(ing.Namespace)},
					{Unmasked: ing.Name, Masked: util.MaskString(ing.Name)},
				},
			})
		}

		sslProtocols := ing.Annotations["nginx.ingress.kubernetes.io/ssl-protocols"]
		if sslProtocols != "" {
			protocols := strings.Fields(sslProtocols)
			for _, disallowed := range disallowedProtocols {
				if containsExact(protocols, disallowed) {
					doc := apiDoc.GetApiDocV2("metadata.annotations")
					failures = append(failures, common.Failure{
						Text:          fmt.Sprintf("Ingress %s/%s allows insecure TLS protocol: %s", ing.Namespace, ing.Name, disallowed),
						KubernetesDoc: doc,
						Sensitive: []common.Sensitive{
							{Unmasked: ing.Namespace, Masked: util.MaskString(ing.Namespace)},
							{Unmasked: ing.Name, Masked: util.MaskString(ing.Name)},
						},
					})
				}
			}
		}

		if len(failures) > 0 {
			preAnalysis[fmt.Sprintf("%s/%s", ing.Namespace, ing.Name)] = common.PreAnalysis{
				FailureDetails: failures,
			}
			AnalyzerErrorsMetric.WithLabelValues(kind, ing.Name, ing.Namespace).Set(float64(len(failures)))
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

func containsExact(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
