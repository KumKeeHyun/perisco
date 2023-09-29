package kubernetes

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type EventHandler interface {
	handleEndpoints(event watch.Event)
	handlePods(event watch.Event)
}

type watcher struct {
	client  corev1.CoreV1Interface
	handler EventHandler

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}

	log *zap.SugaredLogger
}

func NewWatcher(log *zap.SugaredLogger, client corev1.CoreV1Interface, handler EventHandler) *watcher {
	return &watcher{
		client:  client,
		handler: handler,
		log:     log,
	}
}

func (w *watcher) WatchEvents(ctx context.Context) error {
	w.ctx, w.cancel = context.WithCancel(ctx)
	w.donec = make(chan struct{})

	epWatch, err := w.client.Endpoints("").Watch(w.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to watch endpoints: %w", err)
	}
	poWatch, err := w.client.Pods("").Watch(w.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to watch pods: %w", err)
	}

	go func() {
		defer close(w.donec)
		defer epWatch.Stop()
		defer poWatch.Stop()

		for {
			select {
			case event := <-epWatch.ResultChan():
				w.handler.handleEndpoints(event)

			case event := <-poWatch.ResultChan():
				w.handler.handlePods(event)

			case <-w.ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (w *watcher) Stop() error {
	if w.cancel != nil {
		w.cancel()
	}
	<-w.donec
	w.log.Info("watcher stopped")

	err := w.ctx.Err()
	if !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
