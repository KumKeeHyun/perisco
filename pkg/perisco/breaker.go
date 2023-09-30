package perisco

import (
	"github.com/KumKeeHyun/perisco/pkg/ebpf/maps"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"go.uber.org/zap"
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

	log *zap.SugaredLogger
}

func NewProtoDetecter(pm *maps.ProtocolMap, log *zap.SugaredLogger) *protoDetecter {
	return &protoDetecter{
		detected: make(map[types.EndpointKey]types.ProtocolType, 50),
		failed: make(map[types.EndpointKey]struct {
			skipped bool
			cnt     int
		}, 50),
		pm:  pm,
		log: log,
	}
}

var _ Breaker = &protoDetecter{}

// Success implements Breaker
func (pd *protoDetecter) Success(sockKey types.SockKey, protocol types.ProtocolType) {
	ek := sockKey.ToServerEndpoint()
	if pd.alreadyDetected(ek) {
		return
	}

	if err := pd.pm.Detect(ek, protocol); err != nil {
		pd.log.Warnw("failed to update protocol map", "protocol", protocol.String(), "endpoint", ek.String())
		return
	}
	pd.detected[ek] = protocol
	delete(pd.failed, ek)

	pd.log.Infow("detect endpoint", "protocol", protocol.String(), "endpoint", ek.String())
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
	ek := sockKey.ToServerEndpoint()
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
			pd.log.Warnw("failed to update protocol map", "protocol", "SKIP", "endpoint", ek.String())
			failed.skipped = false
		}

		pd.log.Infow("skip endpoint", "endpoint", ek.String())
	}
	pd.failed[ek] = failed
}

func (pd *protoDetecter) alreadySkipped(ek types.EndpointKey) bool {
	if failed, exists := pd.failed[ek]; exists || failed.skipped {
		return true
	}
	return false
}
