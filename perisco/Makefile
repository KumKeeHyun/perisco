TARGET := perisco
BPF_DIR := bpf

.PHONY: all $(TARGET) bpf bin-only clean run

all: $(TARGET)

$(TARGET): bpf
	go build -o $@

bpf:
	make -C $(BPF_DIR)

bin:
	go build -o $(TARGET)

clean:
	rm -f $(TARGET)

run: bin
	sudo ./$(TARGET) run

socktest: bin
	sudo ./$(TARGET) socktest --cidrs=127.0.0.1/32