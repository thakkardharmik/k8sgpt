package analyzer

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type CertificateLifespanAnalyzer struct{}

const certExpiryThresholdDays = 90

func (analyzer CertificateLifespanAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
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

	now := time.Now()
	threshold := now.Add(time.Duration(certExpiryThresholdDays) * 24 * time.Hour)

	for _, secret := range secretList.Items {
		if secret.Type != "kubernetes.io/tls" {
			continue
		}

		certData, ok := secret.Data["tls.crt"]
		if !ok {
			continue
		}

		var failures []common.Failure

		block, _ := pem.Decode(certData)
		if block == nil {
			doc := apiDoc.GetApiDocV2("data")
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("TLS Secret %s/%s contains invalid PEM certificate data", secret.Namespace, secret.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{Unmasked: secret.Namespace, Masked: util.MaskString(secret.Namespace)},
					{Unmasked: secret.Name, Masked: util.MaskString(secret.Name)},
				},
			})
		} else {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				doc := apiDoc.GetApiDocV2("data")
				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("TLS Secret %s/%s contains unparseable certificate: %v", secret.Namespace, secret.Name, err),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{Unmasked: secret.Namespace, Masked: util.MaskString(secret.Namespace)},
						{Unmasked: secret.Name, Masked: util.MaskString(secret.Name)},
					},
				})
			} else {
				if now.After(cert.NotAfter) {
					doc := apiDoc.GetApiDocV2("data")
					failures = append(failures, common.Failure{
						Text:          fmt.Sprintf("TLS Secret %s/%s certificate has expired on %s", secret.Namespace, secret.Name, cert.NotAfter.Format(time.RFC3339)),
						KubernetesDoc: doc,
						Sensitive: []common.Sensitive{
							{Unmasked: secret.Namespace, Masked: util.MaskString(secret.Namespace)},
							{Unmasked: secret.Name, Masked: util.MaskString(secret.Name)},
						},
					})
				} else if cert.NotAfter.Before(threshold) {
					daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
					doc := apiDoc.GetApiDocV2("data")
					failures = append(failures, common.Failure{
						Text:          fmt.Sprintf("TLS Secret %s/%s certificate expires in %d days (on %s)", secret.Namespace, secret.Name, daysLeft, cert.NotAfter.Format(time.RFC3339)),
						KubernetesDoc: doc,
						Sensitive: []common.Sensitive{
							{Unmasked: secret.Namespace, Masked: util.MaskString(secret.Namespace)},
							{Unmasked: secret.Name, Masked: util.MaskString(secret.Name)},
						},
					})
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
