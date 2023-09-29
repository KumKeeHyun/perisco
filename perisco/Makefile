TARGET := perisco
BPF_DIR := bpf

.PHONY: all $(TARGET) bpf bin bin-only clean start

all: $(TARGET)

$(TARGET): bpf
	go build -o $@

bpf:
	make -C $(BPF_DIR)

bin: bpf
	go build -o $(TARGET)

clean:
	rm -f $(TARGET)

bin-only:
	go build -o $(TARGET)

start: bin-only
	sudo ./$(TARGET) start
