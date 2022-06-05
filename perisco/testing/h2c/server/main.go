package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello! from h2c"))
	})

	mux.HandleFunc("/push", func(w http.ResponseWriter, r *http.Request) {
		if data, err := ioutil.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.Write([]byte(fmt.Sprintf("recv: %d", len(data))))
		}
	})

	mux.HandleFunc("/pull", func(w http.ResponseWriter, r *http.Request) {
		data := [4096]byte{}
		for i := 0; i < 3; i++ {
			data[0] = byte(i)
			w.Write(data[:])
		}
	})

	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/greet", http.StatusFound)
	})

	h2s := &http2.Server{}

	server := &http.Server{
		Handler: h2c.NewHandler(mux, h2s),
	}

	l, err := net.Listen("tcp4", ":8881")
	if err != nil {
		log.Fatal(err)
	}
	server.Serve(l)
}
