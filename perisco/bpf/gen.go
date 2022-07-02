package bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel -type ip -type layer4 -type sock_key -type ip_network -type ip_networks -type endpoint_key -type msg_event -no-global-types bpf ./bpfsrc/trace_sock.c -- -I.
