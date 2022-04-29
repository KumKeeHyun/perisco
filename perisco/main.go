package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel -type event bpf $BPF_FILES -- -I$BPF_HEADER

func main() {
	
}