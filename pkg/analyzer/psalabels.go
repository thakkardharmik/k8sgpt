package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type PSALabelsAnalyzer struct{}

var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

func (analyzer PSALabelsAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	kind := "Namespace"
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

	nsList, err := a.Client.GetClient().CoreV1().Namespaces().List(a.Context, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, ns := range nsList.Items {
		if systemNamespaces[ns.Name] {
			continue
		}

		var failures []common.Failure

		enforceLevel, hasEnforce := ns.Labels["pod-security.kubernetes.io/enforce"]

		if !hasEnforce {
			doc := apiDoc.GetApiDocV2("metadata.labels")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("Namespace %s does not have Pod Security Admission enforce label", ns.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: ns.Name, Masked: util.MaskString(ns.Name)},
				},
			})
		} else if enforceLevel != "restricted" && enforceLevel != "baseline" {
			doc := apiDoc.GetApiDocV2("metadata.labels")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("Namespace %s has Pod Security Admission enforce level '%s', expected 'restricted' or 'baseline'", ns.Name, enforceLevel),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: ns.Name, Masked: util.MaskString(ns.Name)},
				},
			})
		}

		if len(failures) > 0 {
			preAnalysis[ns.Name] = common.PreAnalysis{
				FailureDetails: failures,
			}
			AnalyzerErrorsMetric.WithLabelValues(kind, ns.Name, "").Set(float64(len(failures)))
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
