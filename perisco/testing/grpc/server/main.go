package main

import (
	"context"
	"net"

	"google.golang.org/grpc"

	pb "github.com/KumKeeHyun/perisco/perisco/testing/grpc/hello"
)

type server struct {
	pb.UnimplementedHelloServiceServer
}

func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{Msg: "hello! from grpc"}, nil
}

func main() {
	l, err := net.Listen("tcp", "127.0.0.1:8882")
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer()
	pb.RegisterHelloServiceServer(s, &server{})

	if err := s.Serve(l); err != nil {
		panic(err)
	}
}