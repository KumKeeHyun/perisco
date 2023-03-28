package k8stest

import (
	"context"
	"fmt"

	"github.com/KumKeeHyun/perisco/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	keyKubeConfig = "kubeconfig"
	keyType       = "type"
)

func New(vp *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "k8stest",
		Short: "test k8s watch",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runK8STest(vp)
		},
	}

	flags := cmd.Flags()
	flags.String(keyKubeConfig, "/home/kumperisco4/.kube/config", "kube config file")
	flags.String(keyType, "service", "watch resource type: service, pod")
	vp.BindPFlags(flags)

	return cmd
}

func runK8STest(vp *viper.Viper) error {
	log := logger.DefualtLogger.Named("k8stest")

	config, err := clientcmd.BuildConfigFromFlags("", vp.GetString(keyKubeConfig))
	if err != nil {
		log.Fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	switch vp.GetString(keyType) {
	case "service":
		watchService(log, context.Background(), clientset.CoreV1())
	case "pod":
		watchPod(log, context.Background(), clientset.CoreV1())
	default:
		log.Fatalf("invalid resource type")
	}

	return nil
}

func watchService(log *zap.SugaredLogger, ctx context.Context, client corev1.CoreV1Interface) {
	watcher, err := client.Services("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for event := range watcher.ResultChan() {
		svc := event.Object.(*v1.Service)

		switch event.Type {
		case watch.Added:
			fmt.Printf("Service namespace: %s, name: %s added\n%v\n\n", svc.ObjectMeta.Namespace, svc.ObjectMeta.Name, svc.Spec)
		case watch.Modified:
			fmt.Printf("Service namespace: %s, name: %s modified%v\n\n", svc.ObjectMeta.Namespace, svc.ObjectMeta.Name, svc.Spec)
		case watch.Deleted:
			fmt.Printf("Service namespace: %s, name: %s deleted%v\n\n", svc.ObjectMeta.Namespace, svc.ObjectMeta.Name, svc.Spec)
		}
	}
}

func watchPod(log *zap.SugaredLogger, ctx context.Context, client corev1.CoreV1Interface) {
	watcher, err := client.Pods("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for event := range watcher.ResultChan() {
		pod := event.Object.(*v1.Pod)

		switch event.Type {
		case watch.Added:
			fmt.Printf("Pod namespace: %s, name: %s added\n%v\n\n", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, pod.Status)
		case watch.Modified:
			fmt.Printf("Pod namespace: %s, name: %s modified%v\n\n", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, pod.Status)
		case watch.Deleted:
			fmt.Printf("Pod namespace: %s, name: %s deleted%v\n\n", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, pod.Status)
		}
	}
}
