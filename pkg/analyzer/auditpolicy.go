package analyzer

import (
	"fmt"
	"strings"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type AuditPolicyAnalyzer struct{}

func (analyzer AuditPolicyAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
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

		hasAuditPolicy := containsFlag(allArgs, "--audit-policy-file")
		hasAuditLogPath := containsFlag(allArgs, "--audit-log-path")
		hasAuditWebhook := containsFlag(allArgs, "--audit-webhook-config-file")

		if !hasAuditPolicy {
			doc := apiDoc.GetApiDocV2("spec.containers[*].command")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("kube-apiserver %s/%s does not have --audit-policy-file configured", pod.Namespace, pod.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
					{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
				},
			})
		}

		if !hasAuditLogPath && !hasAuditWebhook {
			doc := apiDoc.GetApiDocV2("spec.containers[*].command")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("kube-apiserver %s/%s has no audit backend configured (neither --audit-log-path nor --audit-webhook-config-file)", pod.Namespace, pod.Name),
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

func collectContainerArgs(containers []v1.Container) []string {
	var args []string
	for _, c := range containers {
		args = append(args, c.Command...)
		args = append(args, c.Args...)
	}
	return args
}

func containsFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag || strings.HasPrefix(arg, flag+"=") {
			return true
		}
	}
	return false
}
