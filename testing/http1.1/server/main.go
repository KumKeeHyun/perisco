package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

func main() {
	ipVersion := flag.String("ip", "ipv4", "ipv4, ipv6")
	flag.Parse()

	if *ipVersion != "ipv4" && *ipVersion != "ipv6" {
		panic("invalid ipVersion")
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello! from http/1.1"))
	})

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("."))))

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

	var l net.Listener
	var err error
	if *ipVersion == "ipv4" {
		l, err = net.Listen("tcp4", ":8880")
	} else if *ipVersion == "ipv6" {
		l, err = net.Listen("tcp6", ":8880")
	}
	if err != nil {
		log.Fatal(err)
	}
	http.Serve(l, mux)

}
