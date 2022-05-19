package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8880/test", "url")
	flag.Parse()
	
	resp, err := http.Get(*url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))
}
