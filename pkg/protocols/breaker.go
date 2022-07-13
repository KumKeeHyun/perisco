package protocols

import "github.com/KumKeeHyun/perisco/pkg/ebpf/types"

type Breaker interface {
	Success(types.SockKey, types.ProtocolType)
	Fail(types.SockKey)
}

type mockBreaker struct{}

var _ Breaker = &mockBreaker{}

// Success implements Breaker
func (*mockBreaker) Success(types.SockKey, types.ProtocolType) {}

// Fail implements Breaker
func (*mockBreaker) Fail(types.SockKey) {}
