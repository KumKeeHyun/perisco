package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel bpf $BPF_FILES -- -I$BPF_HEADERS

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM)
	defer cancel()

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	link, err := link.Tracepoint("syscalls", "sys_enter_write", objs.bpfPrograms.HandleTp)
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	fmt.Println("Successfully started!" + 
	"Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` " +
	"to see output of the BPF programs.")

	go func() {
		t := time.NewTicker(time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fmt.Fprintf(os.Stderr, ".")	
			}
		}
	}()

	<-ctx.Done()
}
