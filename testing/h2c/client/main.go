package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

var requests = map[string]func(){
	"greet": greet,
	"push":  push,
	"pull":  pull,
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
	cli := http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	resp, err := cli.Get("http://127.0.0.1:8881/greet")
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

	cli := http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	resp, err := cli.Post("http://127.0.0.1:8881/push", "application/json", bytes.NewBuffer(bJson))
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

func pull() {
	cli := http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	resp, err := cli.Get("http://127.0.0.1:8881/pull")
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

func redir() {
	cli := http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	resp, err := cli.Get("http://127.0.0.1:8881/redir")
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
