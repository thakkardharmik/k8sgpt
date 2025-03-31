package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type HostPathAnalyzer struct{}

var allowedHostPaths = []string{
	"/var/lib/kubelet/pods",
	"/var/run/secrets/kubernetes.io/serviceaccount",
}

func (analyzer HostPathAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	kind := "Pod"
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

	podList, err := a.Client.GetClient().CoreV1().Pods(a.Namespace).List(a.Context, metav1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, pod := range podList.Items {
		var failures []common.Failure
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath != nil {
				allowed := false
				for _, path := range allowedHostPaths {
					if volume.HostPath.Path == path {
						allowed = true
						break
					}
				}

				if !allowed {
					doc := apiDoc.GetApiDocV2("spec.volumes.hostPath")
					failures = append(failures, common.Failure{
						Text:          fmt.Sprintf("Pod %s is using an unapproved HostPath: %s", pod.Name, volume.HostPath.Path),
						KubernetesDoc: doc,
						Sensitive: []common.Sensitive{
							{Unmasked: pod.Namespace, Masked: util.MaskString(pod.Namespace)},
							{Unmasked: pod.Name, Masked: util.MaskString(pod.Name)},
						},
					})
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
