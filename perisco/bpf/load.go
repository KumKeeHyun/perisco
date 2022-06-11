package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func LoadBpfProgram() (chan BpfDataEvent, func()) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
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

	dataRb, err := ringbuf.NewReader(objs.bpfMaps.DataEvents)
	if err != nil {
		log.Fatalf("opening dataEvent ringbuf reader: %s", err)
	}
	dataCh := make(chan BpfDataEvent)
	go func() {
		var dataEvent BpfDataEvent
		for {
			record, err := dataRb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &dataEvent); err != nil {
				log.Printf("parsing closeEvent ringbuf event: %s", err)
				continue
			}

			dataCh <- dataEvent
		}
	}()

	return dataCh, func() {
		dataRb.Close()
		
		fentrySockSendmsg.Close()
		fexitSockRecvmsg.Close()
		fentrySockRecvmsg.Close()
		objs.Close()
	}
}
