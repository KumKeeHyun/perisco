TARGET := perisco
BPF_DIR := bpf

.PHONY: all $(TARGET) bpf bin-only clean run

all: $(TARGET)

$(TARGET): bpf
	go build -o $@

bpf:
	make -C $(BPF_DIR)

bin-only:
	go build -o $(TARGET)

clean:
	rm -f $(TARGET)

run: bin-only
	sudo ./$(TARGET)