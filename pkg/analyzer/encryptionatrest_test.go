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

func TestEncryptionAtRestNotConfigured(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-apiserver-master",
			Namespace: "kube-system",
			Labels: map[string]string{
				"component": "kube-apiserver",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    "kube-apiserver",
					Image:   "registry.k8s.io/kube-apiserver:v1.29.0",
					Command: []string{"kube-apiserver", "--advertise-address=10.0.0.1"},
				},
			},
		},
	})

	config := common.Analyzer{
		Client:  &kubernetes.Client{Client: clientset},
		Context: context.Background(),
	}

	analyzer := EncryptionAtRestAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
	assert.Equal(t, len(results[0].Error), 1)
}

func TestEncryptionAtRestConfiguredNoAutoReload(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-apiserver-master",
			Namespace: "kube-system",
			Labels: map[string]string{
				"component": "kube-apiserver",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "kube-apiserver",
					Image: "registry.k8s.io/kube-apiserver:v1.29.0",
					Command: []string{
						"kube-apiserver",
						"--encryption-provider-config=/etc/kubernetes/encryption.yaml",
					},
				},
			},
		},
	})

	config := common.Analyzer{
		Client:  &kubernetes.Client{Client: clientset},
		Context: context.Background(),
	}

	analyzer := EncryptionAtRestAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
	assert.Equal(t, len(results[0].Error), 1)
}

func TestEncryptionAtRestFullyConfigured(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-apiserver-master",
			Namespace: "kube-system",
			Labels: map[string]string{
				"component": "kube-apiserver",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "kube-apiserver",
					Image: "registry.k8s.io/kube-apiserver:v1.29.0",
					Command: []string{
						"kube-apiserver",
						"--encryption-provider-config=/etc/kubernetes/encryption.yaml",
						"--encryption-provider-config-automatic-reload=true",
					},
				},
			},
		},
	})

	config := common.Analyzer{
		Client:  &kubernetes.Client{Client: clientset},
		Context: context.Background(),
	}

	analyzer := EncryptionAtRestAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}
