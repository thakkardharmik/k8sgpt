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

func TestPSALabelsMissing(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-app",
		},
	})

	config := common.Analyzer{
		Client:  &kubernetes.Client{Client: clientset},
		Context: context.Background(),
	}

	analyzer := PSALabelsAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
}

func TestPSALabelsRestricted(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-app",
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce": "restricted",
			},
		},
	})

	config := common.Analyzer{
		Client:  &kubernetes.Client{Client: clientset},
		Context: context.Background(),
	}

	analyzer := PSALabelsAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}

func TestPSALabelsSkipsSystemNamespaces(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-public"}},
		&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-node-lease"}},
	)

	config := common.Analyzer{
		Client:  &kubernetes.Client{Client: clientset},
		Context: context.Background(),
	}

	analyzer := PSALabelsAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 0)
}

func TestPSALabelsPrivileged(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-app",
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce": "privileged",
			},
		},
	})

	config := common.Analyzer{
		Client:  &kubernetes.Client{Client: clientset},
		Context: context.Background(),
	}

	analyzer := PSALabelsAnalyzer{}
	results, err := analyzer.Analyze(config)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(results), 1)
}
