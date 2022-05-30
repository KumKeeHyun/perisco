package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func LoadBpfProgram() (chan BpfConnEvent, chan BpfCloseEvent, chan BpfDataEvent, func()) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	acceptLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.InetAccept,
	})
	if err != nil {
		log.Fatal(err)
	}
	inetShutdownLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.InetShutdown,
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

	connRb, err := ringbuf.NewReader(objs.bpfMaps.ConnEvents)
	if err != nil {
		log.Fatalf("opening connEvent ringbuf reader: %s", err)
	}
	connCh := make(chan BpfConnEvent)
	go func() {
		var connEvent BpfConnEvent
		for {
			record, err := connRb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &connEvent); err != nil {
				log.Printf("parsing connEvent ringbuf event: %s", err)
				continue
			}

			connCh <- connEvent
		}
	}()

	closeRb, err := ringbuf.NewReader(objs.bpfMaps.CloseEvents)
	if err != nil {
		log.Fatalf("opening closeEvent ringbuf reader: %s", err)
	}
	closeCh := make(chan BpfCloseEvent)
	go func() {
		var closeEvent BpfCloseEvent
		for {
			record, err := closeRb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &closeEvent); err != nil {
				log.Printf("parsing closeEvent ringbuf event: %s", err)
				continue
			}

			closeCh <- closeEvent
		}
	}()

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

	return connCh, closeCh, dataCh, func() {
		dataRb.Close()
		closeRb.Close()
		connRb.Close()

		fentrySockSendmsg.Close()
		fexitSockRecvmsg.Close()
		fentrySockRecvmsg.Close()
		inetShutdownLink.Close()
		acceptLink.Close()
		objs.Close()
	}
}
