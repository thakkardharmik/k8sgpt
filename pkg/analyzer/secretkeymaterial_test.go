package analyzer

import (
	"context"
	"testing"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/magiconair/properties/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretKeyMaterialSuspiciousKey(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
		},
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			"master-key": []byte("some-key-value"),
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := SecretKeyMaterialAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
}

func TestSecretKeyMaterialPEMContent(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pem-secret",
			Namespace: "default",
		},
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			"cert": []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n-----END RSA PRIVATE KEY-----"),
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := SecretKeyMaterialAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
}

func TestSecretKeyMaterialTLSTypeSkipped(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-secret",
			Namespace: "default",
		},
		Type: v1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.key": []byte("-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----"),
			"tls.crt": []byte("cert-data"),
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := SecretKeyMaterialAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}

func TestSecretKeyMaterialClean(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "clean-secret",
			Namespace: "default",
		},
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			"config": []byte("some-config-value"),
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := SecretKeyMaterialAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}
