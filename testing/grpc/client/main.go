package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/KumKeeHyun/perisco/testing/grpc/hello"
)

func main() {
	reqType := flag.String("req", "simple", "simple, sss, css, bds")
	flag.Parse()

	conn, err := grpc.Dial("127.0.0.1:8882",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	c := pb.NewHelloServiceClient(conn)

	switch *reqType {
	case "simple":
		sayHello(c)
	case "sss":
		helloSSS(c)
	case "css":
		helloCSS(c)
	case "bds":
		helloBDS(c)
	default:
		panic("unknown req type")
	}
}

func sayHello(c pb.HelloServiceClient) {
	resp, err := c.SayHello(context.TODO(), &pb.HelloRequest{Msg: "hello"})
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.GetMsg())
}

func helloSSS(c pb.HelloServiceClient) {
	stream, err := c.HelloSSS(context.Background(), &pb.HelloRequest{Msg: "hello"})
	if err != nil {
		panic(err)
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			fmt.Println("end recving sss")
			break
		}
		if err != nil {
			panic(err)
		}
		fmt.Println(resp.Msg)
	}
}

func helloCSS(c pb.HelloServiceClient) {
	stream, err := c.HelloCSS(context.Background())
	if err != nil {
		panic(err)
	}

	iter := rand.Intn(10) + 5
	for i := 0; i < iter; i++ {
		if err := stream.Send(&pb.HelloRequest{Msg: "hello"}); err != nil {
			panic(err)
		}
		fmt.Println("send msg...")
		time.Sleep(time.Second)
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.Msg)
}

func helloBDS(c pb.HelloServiceClient) {
	stream, err := c.HelloBDS(context.Background())
	waitc := make(chan struct{})
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				close(waitc)
				break
			}
			if err != nil {
				panic(err)
			}
			fmt.Println(resp.Msg)
		}
	}()

	iter := rand.Intn(10) + 5
	for i := 0; i < iter; i++ {
		if err := stream.Send(&pb.HelloRequest{
			Msg: fmt.Sprintf("hello %d", i),
		}); err != nil {
			panic(err)
		}
		time.Sleep(time.Second)
	}
	stream.CloseSend()
	<-waitc
}
