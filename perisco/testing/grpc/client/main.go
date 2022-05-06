package main

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/KumKeeHyun/perisco/perisco/testing/grpc/hello"
)

func main() {
	conn, err := grpc.Dial("127.0.0.1:8882", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	c := pb.NewHelloServiceClient(conn)
	resp, err := c.SayHello(context.TODO(), &pb.HelloRequest{Msg: "hello"})
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.GetMsg())
}