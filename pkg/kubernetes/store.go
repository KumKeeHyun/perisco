package kubernetes

import (
	"sync"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/samber/lo"

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

func (s *store) handleEndpoints(event watch.Event) {
	endpoints, ok := event.Object.(*v1.Endpoints)
	if !ok {
		return
	}

	switch event.Type {
	case watch.Added, watch.Modified:
		serviceInfo := &pb.Service{
			Name:      endpoints.Name,
			Namespace: endpoints.Namespace,
			Labels:    lo.MapToSlice(endpoints.Labels, func(k, v string) string { return k + "=" + v }),
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

func (s *store) handlePods(event watch.Event) {
	pod, ok := event.Object.(*v1.Pod)
	if !ok {
		return
	}

	switch event.Type {
	case watch.Added, watch.Modified:
		podInfo := &pb.Endpoint{
			Name:              pod.Name,
			Namespace:         pod.Namespace,
			Labels:            lo.MapToSlice(pod.Labels, func(k, v string) string { return k + "=" + v }),
			NodeName: pod.Spec.NodeName,
		}
		s.pods.Store(pod.Status.PodIP, podInfo)

	case watch.Deleted:
		s.pods.Delete(pod.Status.PodIP)
		s.services.Delete(pod.Status.PodIP)
	}
}

func (s *store) GetPodInfo(ip string) *pb.Endpoint {
	pod, ok := s.pods.Load(ip)
	if !ok {
		return nil
	}
	return pod.(*pb.Endpoint)
}

func (s *store) GetServiceInfo(ip string) *pb.Service {
	svc, ok := s.services.Load(ip)
	if !ok {
		return nil
	}
	return svc.(*pb.Service)
}
