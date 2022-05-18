package bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel -type sock_key -type conn_event -type close_event -type data_event -no-global-types bpf $BPF_FILES -- -I$BPF_HEADERS
