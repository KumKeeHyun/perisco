TARGET := perisco
BPF_DIR := bpf

.PHONY: all $(TARGET) clean run

all: $(TARGET)

$(TARGET):
	make -C $(BPF_DIR)
	go build -o $@

clean:
	rm -f $(TARGET)

run: $(TARGET)
	sudo ./$(TARGET)