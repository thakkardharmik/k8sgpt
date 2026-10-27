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

func TestSTIGImageLatestTag(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "app", Image: "nginx:latest"},
			},
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := STIGImageAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
	assert.Equal(t, len(results[0].Error), 2)
}

func TestSTIGImageDigestPinned(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "app", Image: "nginx@sha256:abc123def456"},
			},
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := STIGImageAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}
