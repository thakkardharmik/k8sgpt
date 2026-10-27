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

func TestTLSMinVersionNoTLS(t *testing.T) {
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

	analyzer := TLSMinVersionAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
	assert.Equal(t, results[0].Error[0].Text, "Ingress default/no-tls has no TLS configuration")
}

func TestTLSMinVersionInsecureProtocol(t *testing.T) {
	clientset := fake.NewSimpleClientset(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "insecure-tls",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/ssl-protocols": "TLSv1 TLSv1.1 TLSv1.2",
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

	analyzer := TLSMinVersionAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
	assert.Equal(t, len(results[0].Error), 2)
}

func TestTLSMinVersionSecure(t *testing.T) {
	clientset := fake.NewSimpleClientset(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secure-tls",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/ssl-protocols": "TLSv1.2 TLSv1.3",
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

	analyzer := TLSMinVersionAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}
