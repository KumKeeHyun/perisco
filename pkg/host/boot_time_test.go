package host

import (
	"testing"
	"time"

	"github.com/shirou/gopsutil/v3/host"
)

func TestBootTime(t *testing.T) {
	uptime, _ := host.Uptime()
	bootTime := time.Unix(int64(uptime), int64(BootTime()))

	errTime := time.Second * 10	
	be := time.Now().Add(-errTime)
	tween := time.Now().Add(errTime)
	
	if bootTime.Before(be) && bootTime.After(tween) {
		t.Errorf("want(+-10sec): %v, got: %v", time.Now(), bootTime)
	}
}
