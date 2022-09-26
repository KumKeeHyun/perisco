package host

import (
	"testing"
	"time"
)

func TestBootTime(t *testing.T) {
	bootTime := time.Unix(0, int64(BootTime()))

	if bootTime.Year() == 1970 {
		t.Error("bootTime must not be 1970")
	}
}
