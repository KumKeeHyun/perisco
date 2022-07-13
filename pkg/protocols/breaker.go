package protocols

import "github.com/KumKeeHyun/perisco/perisco/bpf"

type Breaker interface {
	Success(bpf.SockKey, bpf.ProtocolType)
	Fail(bpf.SockKey)
}

type mockBreaker struct {}

var _ Breaker = &mockBreaker{}

// Success implements Breaker
func (*mockBreaker) Success(bpf.SockKey, bpf.ProtocolType) {}

// Fail implements Breaker
func (*mockBreaker) Fail(bpf.SockKey) {}
