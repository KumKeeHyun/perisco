package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

var requests = map[string]func(){
	"greet": greet,
	"jpg": jpg,
	"push": push,
	"redir": redir,
}

func main() {
	reqType := flag.String("req", "greet", "greet, jpg, push, redirect")
	flag.Parse()
	
	if req, ok := requests[*reqType]; ok {
		req()
	} else {
		log.Fatal("greet, jpg, push, redirect")
	}


}

func greet() {
	resp, err := http.Get("http://127.0.0.1:8880/greet")
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

func jpg() {
	resp, err := http.Get("http://127.0.0.1:8880/static/example.jpg")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println(resp.Status)
}


type pushBody struct {
	Pad1 [2048]byte
	Pad2 string
}

func push() {
	body := make([]pushBody, 5)
	for i, _ := range body {
		body[i].Pad2 = fmt.Sprintf("padding %d!", i)
	}
	bJson, _ := json.Marshal(body)

	resp, err := http.Post("http://127.0.0.1:8880/push", "application/json", bytes.NewBuffer(bJson))
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

func redir() {
	resp, err := http.Get("http://127.0.0.1:8880/redir")
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