package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type DualStackAnalyzer struct{}

func (analyzer DualStackAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	kind := "Service"
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

	svcList, err := a.Client.GetClient().CoreV1().Services(a.Namespace).List(a.Context, metav1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, svc := range svcList.Items {
		if svc.Spec.Type == v1.ServiceTypeExternalName {
			continue
		}

		var failures []common.Failure

		policy := svc.Spec.IPFamilyPolicy
		if policy == nil {
			doc := apiDoc.GetApiDocV2("spec.ipFamilyPolicy")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("Service %s/%s does not specify an ipFamilyPolicy for dual-stack support", svc.Namespace, svc.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: svc.Namespace, Masked: util.MaskString(svc.Namespace)},
					{Unmasked: svc.Name, Masked: util.MaskString(svc.Name)},
				},
			})
		} else if *policy == v1.IPFamilyPolicySingleStack {
			doc := apiDoc.GetApiDocV2("spec.ipFamilyPolicy")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("Service %s/%s uses SingleStack ipFamilyPolicy, dual-stack not enabled", svc.Namespace, svc.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: svc.Namespace, Masked: util.MaskString(svc.Namespace)},
					{Unmasked: svc.Name, Masked: util.MaskString(svc.Name)},
				},
			})
		}

		if len(failures) > 0 {
			preAnalysis[fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)] = common.PreAnalysis{
				FailureDetails: failures,
			}
			AnalyzerErrorsMetric.WithLabelValues(kind, svc.Name, svc.Namespace).Set(float64(len(failures)))
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
