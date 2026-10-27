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

func TestHardcodedCredentialsDetected(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "app",
					Image: "myapp:v1",
					Env: []v1.EnvVar{
						{Name: "DB_PASSWORD", Value: "supersecret123"},
						{Name: "API_TOKEN", Value: "tok-abc123"},
					},
				},
			},
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := HardcodedCredentialsAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
	assert.Equal(t, len(results[0].Error), 2)
}

func TestHardcodedCredentialsSecretRef(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "app",
					Image: "myapp:v1",
					Env: []v1.EnvVar{
						{
							Name: "DB_PASSWORD",
							ValueFrom: &v1.EnvVarSource{
								SecretKeyRef: &v1.SecretKeySelector{
									LocalObjectReference: v1.LocalObjectReference{Name: "db-secret"},
									Key:                  "password",
								},
							},
						},
					},
				},
			},
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := HardcodedCredentialsAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}

func TestHardcodedCredentialsNonSensitiveEnv(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "app",
					Image: "myapp:v1",
					Env: []v1.EnvVar{
						{Name: "LOG_LEVEL", Value: "debug"},
						{Name: "PORT", Value: "8080"},
					},
				},
			},
		},
	})

	config := common.Analyzer{
		Client:    &kubernetes.Client{Client: clientset},
		Context:   context.Background(),
		Namespace: "default",
	}

	analyzer := HardcodedCredentialsAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}
