package protocols

import (
	"log"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/maps"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

type Breaker interface {
	Success(types.SockKey, types.ProtocolType)
	Fail(types.SockKey)
}

type mockBreaker struct {
	scnt, fcnt int
}

var _ Breaker = &mockBreaker{}

// Success implements Breaker
func (mb *mockBreaker) Success(types.SockKey, types.ProtocolType) { mb.scnt++ }

// Fail implements Breaker
func (mb *mockBreaker) Fail(types.SockKey) { mb.fcnt++ }

type protoDetecter struct {
	detected map[types.EndpointKey]types.ProtocolType
	failed   map[types.EndpointKey]struct {
		skipped bool
		cnt     int
	}
	pm *maps.ProtocolMap
}

func NewProtoDetecter(pm *maps.ProtocolMap) *protoDetecter {
	return &protoDetecter{
		detected: make(map[types.EndpointKey]types.ProtocolType, 50),
		failed: make(map[types.EndpointKey]struct {
			skipped bool
			cnt     int
		}, 50),
		pm: pm,
	}
}

var _ Breaker = &protoDetecter{}

// Success implements Breaker
func (pd *protoDetecter) Success(sockKey types.SockKey, protocol types.ProtocolType) {
	ek := sockKey.ToEndpointKey()
	if pd.alreadyDetected(ek) {
		return
	}

	if err := pd.pm.Detect(ek, protocol); err != nil {
		// TODO: logging warning
		log.Println(err)
		return
	}
	pd.detected[ek] = protocol
	delete(pd.failed, ek)

	log.Printf("detected %s in endpoint(%s)\n", protocol.String(), ek.String())
}

func (pd *protoDetecter) alreadyDetected(ek types.EndpointKey) bool {
	if _, exists := pd.detected[ek]; exists {
		return true
	}
	return false
}

const failureThreshold = 10

// Fail implements Breaker
func (pd *protoDetecter) Fail(sockKey types.SockKey) {
	ek := sockKey.ToEndpointKey()
	if pd.alreadyDetected(ek) {
		return
	}

	failed, exists := pd.failed[ek]
	if !exists {
		pd.failed[ek] = struct {
			skipped bool
			cnt     int
		}{
			skipped: false,
			cnt:     1,
		}
		return
	} else if failed.skipped {
		return
	}

	failed.cnt++
	if failed.cnt >= failureThreshold {
		failed.skipped = true
		if err := pd.pm.Skip(ek); err != nil {
			// TODO: logging warning
			log.Println(err)
			failed.skipped = false
		}

		log.Printf("start to skip endpoint(%s)\n", ek.String())
	}
	pd.failed[ek] = failed
}

func (pd *protoDetecter) alreadySkipped(ek types.EndpointKey) bool {
	if failed, exists := pd.failed[ek]; exists || failed.skipped {
		return true
	}
	return false
}