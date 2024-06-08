BPF_SOURCES := ebpf_program.c
BPF_TARGET := ../build/ebpf_program.o

all: $(BPF_TARGET)

$(BPF_TARGET): $(BPF_SOURCES)
	clang -O2 -target bpf -c $< -o $@

clean:
	rm -f $(BPF_TARGET)

.PHONY: all clean
