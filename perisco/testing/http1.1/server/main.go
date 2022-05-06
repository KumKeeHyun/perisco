package main

import "net/http"

func main() {
	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello! from http/1.1"))
	})

	http.ListenAndServe("127.0.0.1:8880", nil)
}