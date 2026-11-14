ARCH_INC := -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: gen sensor test clean
gen:
	go mod tidy
	go build -o bin/depguard-gen ./cmd/depguard-gen
sensor:   ## needs clang, libbpf-dev, linux-libc-dev; kernel >= 5.8
	cd sensor && go mod tidy
	cd sensor && BPF2GO_CFLAGS="$(ARCH_INC)" go generate ./...
	cd sensor && go build -o ../bin/depguard-sensor .
test: gen
	./test/attack_simulation.sh
clean:
	rm -rf bin sensor/bpf_bpf*.go sensor/bpf_bpf*.o
