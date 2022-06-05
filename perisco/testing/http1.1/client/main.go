package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
)

var requests = map[string]func(string){
	"greet": greet,
	"jpg":   jpg,
	"push":  push,
	"pull":  pull,
	"redir": redir,
}

func main() {
	reqType := flag.String("req", "greet", "greet, jpg, push, redirect")
	ipVersion := flag.String("ip", "ipv4", "ipv4, ipv6")
	flag.Parse()

	var addr string
	if *ipVersion == "ipv4" {
		addr = "127.0.0.1"
	} else if *ipVersion == "ipv6"{
		addr = "::1"
	} else {
		panic("invalid ipVersion")
	}

	if req, ok := requests[*reqType]; ok {
		req(addr)
	} else {
		panic("greet, jpg, push, redirect")
	}
}

func greet(addr string) {
	resp, err := http.Get(fmt.Sprintf("http://%s:8880/greet", addr))
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

func jpg(addr string) {
	resp, err := http.Get(fmt.Sprintf("http://%s:8880/static/example.jpg", addr))
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

func push(addr string) {
	body := make([]pushBody, 5)
	for i, _ := range body {
		body[i].Pad2 = fmt.Sprintf("padding %d!", i)
	}
	bJson, _ := json.Marshal(body)

	resp, err := http.Post(fmt.Sprintf("http://%s:8880/push", addr), "application/json", bytes.NewBuffer(bJson))
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

func pull(addr string) {
	resp, err := http.Get(fmt.Sprintf("http://%s:8880/pull", addr))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.Status, len(data))
}

func redir(addr string) {
	resp, err := http.Get(fmt.Sprintf("http://%s:8880/redir", addr))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(data))
}
