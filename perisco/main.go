package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM)
	defer cancel()

	connCh, closeCh, dataCh, clean := bpf.LoadBpfProgram()
	defer clean()

	go func() {
		for {
			select {
			case connEvent := <-connCh:
				log.Printf("%-15s %-6d   %-15s %-6d  %-10s",
					connEvent.SockKey.GetSrcIpv4(),
					connEvent.SockKey.Sport,
					connEvent.SockKey.GetDstIpv4(),
					connEvent.SockKey.Dport,
					"CONN",
				)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case closeEvent := <-closeCh:
				log.Printf("%-15s %-6d   %-15s %-6d  %-10s  %-10d %-10d ",
					closeEvent.SockKey.GetSrcIpv4(),
					closeEvent.SockKey.Sport,
					closeEvent.SockKey.GetDstIpv4(),
					closeEvent.SockKey.Dport,
					"CLOSE",
					closeEvent.SendBytes,
					closeEvent.RecvBytes,
				)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case dataEvent := <-dataCh:
				if dataEvent.SockKey.Dport == 443 {
					continue
				}

				// filter response
				// if dataEvent.MsgType != 0 {
				// 	continue
				// }

				rawLogging(dataEvent)
				// parseHttp1AndLogging(dataEvent)
				// parseHttp2AndLogging(dataEvent)

				
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
}

func rawLogging(dataEvent *bpf.BpfDataEvent) {
	log.Printf("%-15s %-6d   %-15s %-6d  %-10s %d\nnr_segs: %d, count: %d, iov_offset: %d, iov_idx: %d\nret: %d, size: %d, msg: %s\n",
		dataEvent.SockKey.GetSrcIpv4(),
		dataEvent.SockKey.Sport,
		dataEvent.SockKey.GetDstIpv4(),
		dataEvent.SockKey.Dport,
		bpf.IntToMsgType(dataEvent.MsgType),
		dataEvent.SockKey.Family,
		dataEvent.IterNrSegs,
		dataEvent.IterCount,
		dataEvent.IterOffset,
		dataEvent.IovIdx,
		dataEvent.Ret,
		dataEvent.MsgSize,
		dataEvent.Msg[:dataEvent.MsgSize],
	)
}

func parseHttp1AndLogging(event *bpf.BpfDataEvent) {
	rb := bufio.NewReader(bytes.NewReader(event.Msg[:]))
	
	if event.MsgType == 0 {
		req, err := http.ReadRequest(rb)
		if err != nil {
			return 
		}
		req.Body.Close()

		log.Printf("%-15s %-6d   %-15s %-6d  %-10s\nret: %-5d [%-10s %-15s %-10s %s header: %v]\n",
			event.SockKey.GetSrcIpv4(),
			event.SockKey.Sport,
			event.SockKey.GetDstIpv4(),
			event.SockKey.Dport,
			bpf.IntToMsgType(event.MsgType),
			event.Ret,
			req.Proto,
			req.Host,
			req.Method,
			req.URL.Path,
			req.Header,
		)

	} else if event.MsgType == 1 {
		resp, err := http.ReadResponse(rb, nil)
		if err != nil {
			return
		}
		resp.Body.Close()

		log.Printf("%-15s %-6d   %-15s %-6d  %-10s\nret: %-5d [%-10s %-15s header: %v]\n",
			event.SockKey.GetSrcIpv4(),
			event.SockKey.Sport,
			event.SockKey.GetDstIpv4(),
			event.SockKey.Dport,
			bpf.IntToMsgType(event.MsgType),
			event.Ret,
			resp.Proto,
			resp.Status,
			resp.Header,
		)
	} else {
		return
	}
}

func parseHttp2AndLogging(event *bpf.BpfDataEvent) {
	r := bytes.NewReader(event.Msg[:])
	
	preface := make([]byte, len(http2.ClientPreface))
	r.Read(preface)
	if !bytes.Equal(preface, []byte(http2.ClientPreface)) {
		r.Seek(0, 0)
	} 
	
	framer := http2.NewFramer(io.Discard, r)

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}	
		loggingFrame(frame, event)
	}
	
}

func loggingFrame(frame http2.Frame, event *bpf.BpfDataEvent) {
	if headers, ok := frame.(*http2.HeadersFrame); ok {
		decoded, _ := hpack.NewDecoder(2048, nil).DecodeFull(headers.HeaderBlockFragment())
		log.Printf("%-15s %-6d   %-15s %-6d  %-10s\nret: %-5d %v\n",
			event.SockKey.GetSrcIpv4(),
			event.SockKey.Sport,
			event.SockKey.GetDstIpv4(),
			event.SockKey.Dport,
			bpf.IntToMsgType(event.MsgType),
			event.Ret,
			decoded,
		)
	} else if datas, ok := frame.(*http2.DataFrame); ok {
		log.Printf("%-15s %-6d   %-15s %-6d  %-10s\nret: %-5d [DataFrame %s]\n",
			event.SockKey.GetSrcIpv4(),
			event.SockKey.Sport,
			event.SockKey.GetDstIpv4(),
			event.SockKey.Dport,
			bpf.IntToMsgType(event.MsgType),
			event.Ret,
			datas.Data(),
		)
	} else {
		log.Printf("%-15s %-6d   %-15s %-6d  %-10s\nret: %-5d %v\n",
			event.SockKey.GetSrcIpv4(),
			event.SockKey.Sport,
			event.SockKey.GetDstIpv4(),
			event.SockKey.Dport,
			bpf.IntToMsgType(event.MsgType),
			event.Ret,
			frame,
		)
	} 
}