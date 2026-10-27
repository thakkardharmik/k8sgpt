package analyzer

import (
	"context"
	"testing"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/magiconair/properties/assert"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestACMECertificateNoCertManager(t *testing.T) {
	clientset := fake.NewSimpleClientset(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"example.com"}, SecretName: "tls-secret"},
			},
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := ACMECertificateAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
}

func TestACMECertificateWithCertManager(t *testing.T) {
	clientset := fake.NewSimpleClientset(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"cert-manager.io/cluster-issuer": "letsencrypt-prod",
			},
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"example.com"}, SecretName: "tls-secret"},
			},
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := ACMECertificateAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}

func TestACMECertificateNoTLSSkipped(t *testing.T) {
	clientset := fake.NewSimpleClientset(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-tls",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{Host: "example.com"},
			},
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := ACMECertificateAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}
