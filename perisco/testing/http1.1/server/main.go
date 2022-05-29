package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

func main() {
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

	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/greet", http.StatusFound)
	})

	l, err := net.Listen("tcp4", ":8880")
	if err != nil {
		log.Fatal(err)
	}
	http.Serve(l, mux)

	// http.ListenAndServe("0.0.0.0:8880", mux)
}
