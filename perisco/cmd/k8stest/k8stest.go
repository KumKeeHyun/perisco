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
	keyNamespace  = "namespace"
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
	flags.String(keyType, "pod", "watch resource type: service, pod")
	flags.String(keyNamespace, "default", "watch resource namespace")
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
	case "node":
		watchNode(log, context.Background(), clientset.CoreV1())
	case "endpoint":
		watchEndpoint(log, context.Background(), clientset.CoreV1(), vp.GetString(keyNamespace))
	case "service":
		watchService(log, context.Background(), clientset.CoreV1(), vp.GetString(keyNamespace))
	case "pod":
		watchPod(log, context.Background(), clientset.CoreV1(), vp.GetString(keyNamespace))
	default:
		log.Fatalf("invalid resource type")
	}

	return nil
}

func watchNode(log *zap.SugaredLogger, ctx context.Context, client corev1.CoreV1Interface) {
	watcher, err := client.Nodes().Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for event := range watcher.ResultChan() {
		node := event.Object.(*v1.Node)

		switch event.Type {
		case watch.Added:
			fmt.Printf("Node namespace: %s, name: %s added\nspec:%v\nstatus:%v\n\n", node.ObjectMeta.Namespace, node.ObjectMeta.Name, node.Spec.String(), node.Status.String())
		case watch.Modified:
			fmt.Printf("Node namespace: %s, name: %s modified\nspec:%v\nstatus:%v\n\n", node.ObjectMeta.Namespace, node.ObjectMeta.Name, node.Spec.String(), node.Status.String())
		case watch.Deleted:
			fmt.Printf("Node namespace: %s, name: %s deleted\nspec:%v\nstatus:%v\n\n", node.ObjectMeta.Namespace, node.ObjectMeta.Name, node.Spec.String(), node.Status.String())
		}
	}
}

func watchEndpoint(log *zap.SugaredLogger, ctx context.Context, client corev1.CoreV1Interface, namespace string) {
	watcher, err := client.Endpoints(namespace).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for event := range watcher.ResultChan() {
		endpoint := event.Object.(*v1.Endpoints)

		switch event.Type {
		case watch.Added:
			fmt.Printf("Endpoint namespace: %s, name: %s added\nsubsets:%v\n\n", endpoint.ObjectMeta.Namespace, endpoint.ObjectMeta.Name, endpoint.Subsets)
		case watch.Modified:
			fmt.Printf("Endpoint namespace: %s, name: %s modified\nsubsets:%v\n\n", endpoint.ObjectMeta.Namespace, endpoint.ObjectMeta.Name, endpoint.Subsets)
		case watch.Deleted:
			fmt.Printf("Endpoint namespace: %s, name: %s deleted\nsubsets:%v\n\n", endpoint.ObjectMeta.Namespace, endpoint.ObjectMeta.Name, endpoint.Subsets)
		}
	}
}

func watchService(log *zap.SugaredLogger, ctx context.Context, client corev1.CoreV1Interface, namespace string) {
	watcher, err := client.Services(namespace).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for event := range watcher.ResultChan() {
		svc := event.Object.(*v1.Service)

		switch event.Type {
		case watch.Added:
			fmt.Printf("Service namespace: %s, name: %s added\nspec:%v\nstatus:%v\n\n", svc.ObjectMeta.Namespace, svc.ObjectMeta.Name, svc.Spec.String(), svc.Status.String())
		case watch.Modified:
			fmt.Printf("Service namespace: %s, name: %s modified\nspec:%v\nstatus:%v\n\n", svc.ObjectMeta.Namespace, svc.ObjectMeta.Name, svc.Spec.String(), svc.Status.String())
		case watch.Deleted:
			fmt.Printf("Service namespace: %s, name: %s deleted\nspec:%v\nstatus:%v\n\n", svc.ObjectMeta.Namespace, svc.ObjectMeta.Name, svc.Spec.String(), svc.Status.String())
		}
	}
}

func watchPod(log *zap.SugaredLogger, ctx context.Context, client corev1.CoreV1Interface, namespace string) {
	watcher, err := client.Pods(namespace).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for event := range watcher.ResultChan() {
		pod := event.Object.(*v1.Pod)

		switch event.Type {
		case watch.Added:
			fmt.Printf("Pod namespace: %s, name: %s added\nspec:%v\nstatus:%v\n\n", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, pod.Spec.String(), pod.Status.String())
		case watch.Modified:
			fmt.Printf("Pod namespace: %s, name: %s modified\nspec:%v\nstatus:%v\n\n", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, pod.Spec.String(), pod.Status.String())
		case watch.Deleted:
			fmt.Printf("Pod namespace: %s, name: %s deleted\nspec:%v\nstatus:%v\n\n", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, pod.Spec.String(), pod.Status.String())
		}
	}
}