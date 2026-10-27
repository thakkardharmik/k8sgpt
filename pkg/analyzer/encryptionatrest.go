package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type EncryptionAtRestAnalyzer struct{}

func (analyzer EncryptionAtRestAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
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

	podList, err := a.Client.GetClient().CoreV1().Pods("kube-system").List(a.Context, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	if len(podList.Items) == 0 {
		preAnalysis["kube-system/kube-apiserver"] = common.PreAnalysis{
			FailureDetails: []common.Failure{
				{
					Text: "No kube-apiserver pod found in kube-system namespace (may be running outside the cluster or using a managed control plane)",
				},
			},
		}
	}

	for _, pod := range podList.Items {
		var failures []common.Failure

		allArgs := collectContainerArgs(pod.Spec.Containers)

		hasEncryptionConfig := containsFlag(allArgs, "--encryption-provider-config")

		if !hasEncryptionConfig {
			doc := apiDoc.GetApiDocV2("spec.containers[*].command")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("kube-apiserver %s/%s does not have --encryption-provider-config set (data at rest is not encrypted)", pod.Namespace, pod.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
					{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
				},
			})
		}

		hasAutoReload := containsFlag(allArgs, "--encryption-provider-config-automatic-reload")
		if hasEncryptionConfig && !hasAutoReload {
			doc := apiDoc.GetApiDocV2("spec.containers[*].command")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("kube-apiserver %s/%s has encryption at rest but --encryption-provider-config-automatic-reload is not enabled (key rotation requires manual restart)", pod.Namespace, pod.Name),
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
