package main

import "net/http"

func main() {
	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello! from http/1.1"))
	})

	http.ListenAndServe("0.0.0.0:8880", nil)
}