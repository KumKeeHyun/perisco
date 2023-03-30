package kubernetes

import (
	"fmt"
	"sync"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type store struct {
	pods     *sync.Map
	services *sync.Map
}

func NewStore() *store {
	return &store{
		pods:     &sync.Map{},
		services: &sync.Map{},
	}
}

func (s *store) handleWatchEndpoints(event watch.Event) {
	endpoints, ok := event.Object.(*v1.Endpoints)
	if !ok {
		return
	}

	switch event.Type {
	case watch.Added, watch.Modified:
		serviceInfo := Service{
			Name:      endpoints.Name,
			NameSpace: endpoints.Namespace,
		}
		for _, subset := range endpoints.Subsets {
			for _, endpoint := range subset.Addresses {
				s.services.Store(endpoint.IP, serviceInfo)
			}
		}

	case watch.Deleted:
	}
}

type Service struct {
	Name      string
	NameSpace string
}

type Pod struct {
	Name      string
	Namespace string
	Labels    []string
	Service   *Service
}

// func (s *store) handleWatchServices(event watch.Event) {

// }

func (s *store) handleWatchPods(event watch.Event) {
	pod, ok := event.Object.(*v1.Pod)
	if !ok {
		return
	}

	switch event.Type {
	case watch.Added, watch.Modified:
		podInfo := Pod{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Labels:    []string{},
		}
		for k, v := range pod.Labels {
			podInfo.Labels = append(podInfo.Labels, fmt.Sprintf("%s=%s", k, v))
		}
		s.pods.Store(pod.Status.PodIP, podInfo)

	case watch.Deleted:
		s.pods.Delete(pod.Status.PodIP)
	}
}

func (s *store) GetPodInfo(ip string) *pb.Endpoint {
	pod, ok := s.pods.Load(ip)
	if !ok {
		return nil
	}
	podInfo := pod.(Pod)
	return &pb.Endpoint{
		Namespace: podInfo.Namespace,
		Labels:    podInfo.Labels,
		PodName:   podInfo.Name,
	}
}

func (s *store) GetServiceInfo(ip string) *pb.Service {
	svc, ok := s.services.Load(ip)
	if !ok {
		return nil
	}
	svcInfo := svc.(Service)
	return &pb.Service{
		Name:      svcInfo.Name,
		Namespace: svcInfo.NameSpace,
	}
}
