package host

import (
	"time"

	"github.com/KumKeeHyun/perisco/pkg/logger"
	"github.com/shirou/gopsutil/v3/host"
)

var bootTime uint64

func init() {
	uptime, err := host.Uptime()
	if err != nil {
		panic(err)
	}
	bootTime = uint64(time.Now().Add(-time.Second * time.Duration(uptime)).UnixNano())
	logger.DefualtLogger.Named("bootTime").Infof("system boot time is %v", time.Unix(0, int64(bootTime)))
}

func BootTime() uint64 {
	return bootTime
}
