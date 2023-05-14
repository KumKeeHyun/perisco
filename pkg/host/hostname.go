package host

import "os"

func MustGetHostname() string {
	hn, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	return hn
}
