package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"runtime"
	"sync"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/maps"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

var msgEventPool = sync.Pool{
	New: func() interface{} { return &types.MsgEvent{} },
}

func LoadBpfProgram() (chan *types.MsgEvent, chan *types.MsgEvent, *maps.NetworkFilter, *maps.ProtocolMap, func()) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	fentryInetAccept, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.FexitInetAccept,
	})
	if err != nil {
		log.Fatal(err)
	}
	fentrySockRecvmsg, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.FentrySockRecvmsg,
	})
	if err != nil {
		log.Fatal(err)
	}
	fexitSockRecvmsg, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.FexitSockRecvmsg,
	})
	if err != nil {
		log.Fatal(err)
	}

	fentrySockSendmsg, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.FentrySockSendmsg,
	})
	if err != nil {
		log.Fatal(err)
	}

	recvRb, err := ringbuf.NewReader(objs.bpfMaps.RecvmsgEvents)
	if err != nil {
		log.Fatalf("opening dataEvent ringbuf reader: %s", err)
	}
	recvCh := make(chan *types.MsgEvent)
	go func() {
		for {
			record, err := recvRb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			msgEvent := msgEventPool.Get().(*types.MsgEvent)
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, msgEvent); err != nil {
				log.Printf("parsing closeEvent ringbuf event: %s", err)
				continue
			}
			runtime.SetFinalizer(msgEvent, func(obj interface{}) {
				msgEventPool.Put(obj)
			})

			recvCh <- msgEvent
		}
	}()

	sendRb, err := ringbuf.NewReader(objs.bpfMaps.SendmsgEvents)
	if err != nil {
		log.Fatalf("opening dataEvent ringbuf reader: %s", err)
	}
	sendCh := make(chan *types.MsgEvent)
	go func() {
		for {
			record, err := sendRb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			msgEvent := msgEventPool.Get().(*types.MsgEvent)
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, msgEvent); err != nil {
				log.Printf("parsing closeEvent ringbuf event: %s", err)
				continue
			}
			runtime.SetFinalizer(msgEvent, func(obj interface{}) {
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
