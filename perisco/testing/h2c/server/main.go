package main

import (
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello! from h2c"))
	})

	h2s := &http2.Server{}

	// server := &http.Server{
	// 	Addr:    "127.0.0.1:8881",
	// 	Handler: h2c.NewHandler(handler, h2s),
	// }

	// server.ListenAndServe()

	l, err := net.Listen("tcp", "127.0.0.1:8881")
	if err != nil {
		panic(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		h2s.ServeConn(conn, &http2.ServeConnOpts{
			Handler: handler,
		})
	}
}
