package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ACMECertificateAnalyzer struct{}

var certManagerAnnotations = []string{
	"cert-manager.io/cluster-issuer",
	"cert-manager.io/issuer",
	"certmanager.k8s.io/cluster-issuer",
	"certmanager.k8s.io/issuer",
}

func (analyzer ACMECertificateAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
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
		if len(ing.Spec.TLS) == 0 {
			continue
		}

		var failures []common.Failure

		hasCertManager := false
		for _, annotation := range certManagerAnnotations {
			if _, ok := ing.Annotations[annotation]; ok {
				hasCertManager = true
				break
			}
		}

		if !hasCertManager {
			doc := apiDoc.GetApiDocV2("metadata.annotations")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("Ingress %s/%s has TLS configured but no cert-manager annotation for automated ACME certificate management", ing.Namespace, ing.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: ing.Namespace, Masked: util.MaskString(ing.Namespace)},
					{Unmasked: ing.Name, Masked: util.MaskString(ing.Name)},
				},
			})
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
