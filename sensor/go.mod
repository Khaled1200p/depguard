module github.com/depguard/depguard/sensor

go 1.22

require (
	github.com/cilium/ebpf v0.16.0
	github.com/depguard/depguard v0.0.0
)

replace github.com/depguard/depguard => ../
