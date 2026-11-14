ARCH_INC := -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: gen sensor test clean
gen:      ## zero-dependency baseline generator
	go build -o bin/depguard-gen ./cmd/depguard-gen
sensor:   ## needs: clang, libbpf-dev, linux-headers, kernel >= 5.8 (ringbuf) with BTF not required
	cd sensor && go mod tidy && BPF2GO_CFLAGS="$(ARCH_INC)" go generate ./... && go build -o ../bin/depguard-sensor .
test: gen ## attack simulation (run with sudo to include the eBPF tier)
	./test/attack_simulation.sh
clean:
	rm -rf bin sensor/bpf_bpf*.go sensor/bpf_bpf*.o
