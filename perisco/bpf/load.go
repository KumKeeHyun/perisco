package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/maps"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/host"
	"github.com/KumKeeHyun/perisco/pkg/logger"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

var msgEventPool = sync.Pool{
	New: func() interface{} {
		msgEventPoolNew.Inc()
		return &types.MsgEvent{}
	},
}

func LoadBpfProgram() (chan *types.MsgEvent, chan *types.MsgEvent, *maps.NetworkFilter, *maps.ProtocolMap, func()) {
	log := logger.DefualtLogger.Named("bpfLoader")

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalw("failed to load bpf object", "err", err)
	}

	fentryInetAccept, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.FexitInetAccept,
	})
	if err != nil {
		log.Fatalw("failed to attach tracing fexit/inet_accept", "err", err)
	}
	fentrySockRecvmsg, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.FentrySockRecvmsg,
	})
	if err != nil {
		log.Fatalw("failed to attach tracing fencty/sock_recvmsg", "err", err)
	}
	fexitSockRecvmsg, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.FexitSockRecvmsg,
	})
	if err != nil {
		log.Fatalw("failed to attach tracing fexit/sock_recvmsg", "err", err)
	}

	fentrySockSendmsg, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.FentrySockSendmsg,
	})
	if err != nil {
		log.Fatalw("failed to attach tracing fentry/sock_sendmsg", "err", err)
	}

	recvRb, err := ringbuf.NewReader(objs.bpfMaps.RecvmsgEvents)
	if err != nil {
		log.Fatalw("failed to open recvmsg ringbuf", "err", err)
	}
	recvCh := make(chan *types.MsgEvent)
	go func() {
		for {
			record, err := recvRb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Info("recvmsg reader stopped")
					return
				}
				log.Errorw("failed to read recvmsg ringbuf", "err", err)
				continue
			}
			recvmsgEvents.Inc()

			msgEvent := msgEventPool.Get().(*types.MsgEvent)
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, msgEvent); err != nil {
				log.Errorw("failed to read recvmsg event", "err", err)
				continue
			}
			msgEvent.Timestamp += host.BootTime()
			runtime.SetFinalizer(msgEvent, func(obj interface{}) {
				msgEventPoolPut.Inc()
				msgEventPool.Put(obj)
			})

			recvCh <- msgEvent
		}
	}()

	sendRb, err := ringbuf.NewReader(objs.bpfMaps.SendmsgEvents)
	if err != nil {
		log.Fatalw("failed to open sendmsg ringbuf", "err", err)
	}
	sendCh := make(chan *types.MsgEvent)
	go func() {
		for {
			record, err := sendRb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Info("sendmsg reader stopped")
					return
				}
				log.Errorw("failed to read sendmsg ringbuf", "err", err)
				continue
			}
			sendmsgEvents.Inc()

			msgEvent := msgEventPool.Get().(*types.MsgEvent)
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, msgEvent); err != nil {
				log.Errorw("failed to read sendmsg event", "err", err)
				continue
			}
			msgEvent.Timestamp += host.BootTime()
			runtime.SetFinalizer(msgEvent, func(obj interface{}) {
				msgEventPoolPut.Inc()
				msgEventPool.Put(obj)
			})

			sendCh <- msgEvent
		}
	}()

	return recvCh, sendCh,
		maps.NewNetworkFilterFromEBPF(objs.NetworkFilter),
		maps.NewProtocolMapFromEBPF(objs.ProtocolMap),
		func() {
			sendRb.Close()
			recvRb.Close()

			fentrySockSendmsg.Close()
			fexitSockRecvmsg.Close()
			fentrySockRecvmsg.Close()
			fentryInetAccept.Close()

			objs.Close()
		}
}
