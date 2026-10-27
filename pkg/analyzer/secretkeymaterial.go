package analyzer

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type SecretKeyMaterialAnalyzer struct{}

var suspiciousKeyPatterns = []string{
	"kek", "master-key", "master_key", "masterkey",
	"encryption-key", "encryption_key", "encryptionkey",
	"private-key", "private_key", "privatekey",
	"signing-key", "signing_key", "signingkey",
}

var pemHeaders = []string{
	"-----BEGIN RSA PRIVATE KEY-----",
	"-----BEGIN EC PRIVATE KEY-----",
	"-----BEGIN PRIVATE KEY-----",
	"-----BEGIN ENCRYPTED PRIVATE KEY-----",
}

func (analyzer SecretKeyMaterialAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	kind := "Secret"
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

	secretList, err := a.Client.GetClient().CoreV1().Secrets(a.Namespace).List(a.Context, metav1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, secret := range secretList.Items {
		if secret.Type == "kubernetes.io/service-account-token" || secret.Type == "kubernetes.io/tls" {
			continue
		}

		var failures []common.Failure

		for dataKey, dataValue := range secret.Data {
			lowerKey := strings.ToLower(dataKey)
			for _, pattern := range suspiciousKeyPatterns {
				if strings.Contains(lowerKey, pattern) {
					doc := apiDoc.GetApiDocV2("data")
					failures = append(failures, common.Failure{
						Text:          fmt.Sprintf("Secret %s/%s has data key '%s' matching key encryption material pattern '%s'", secret.Namespace, secret.Name, dataKey, pattern),
						KubernetesDoc: doc,
						Sensitive: []common.Sensitive{
							{Unmasked: secret.Namespace, Masked: util.MaskString(secret.Namespace)},
							{Unmasked: secret.Name, Masked: util.MaskString(secret.Name)},
							{Unmasked: dataKey, Masked: util.MaskString(dataKey)},
						},
					})
					break
				}
			}

			decoded := string(dataValue)
			if !strings.HasPrefix(decoded, "-----BEGIN") {
				if decoded64, err := base64.StdEncoding.DecodeString(string(dataValue)); err == nil {
					decoded = string(decoded64)
				}
			}

			for _, header := range pemHeaders {
				if strings.Contains(decoded, header) {
					doc := apiDoc.GetApiDocV2("data")
					failures = append(failures, common.Failure{
						Text:          fmt.Sprintf("Secret %s/%s contains private key material (PEM) in key '%s'", secret.Namespace, secret.Name, dataKey),
						KubernetesDoc: doc,
						Sensitive: []common.Sensitive{
							{Unmasked: secret.Namespace, Masked: util.MaskString(secret.Namespace)},
							{Unmasked: secret.Name, Masked: util.MaskString(secret.Name)},
							{Unmasked: dataKey, Masked: util.MaskString(dataKey)},
						},
					})
					break
				}
			}
		}

		if len(failures) > 0 {
			preAnalysis[fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)] = common.PreAnalysis{
				FailureDetails: failures,
			}
			AnalyzerErrorsMetric.WithLabelValues(kind, secret.Name, secret.Namespace).Set(float64(len(failures)))
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
