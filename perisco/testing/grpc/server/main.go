package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"google.golang.org/grpc"

	pb "github.com/KumKeeHyun/perisco/perisco/testing/grpc/hello"
)

type server struct {
	pb.UnimplementedHelloServiceServer
}

func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{Msg: "hello! from grpc"}, nil
}

func (s *server) HelloSSS(req *pb.HelloRequest, stream pb.HelloService_HelloSSSServer) error {
	for i := 0; i < 5; i++ {
		if err := stream.Send(&pb.HelloResponse{
			Msg: fmt.Sprintf("hello! from grpc %d", i),
		}); err != nil {
			return err
		}
		time.Sleep(time.Second)
	}
	return nil
}
func (s *server) HelloCSS(stream pb.HelloService_HelloCSSServer) error {
	cnt := 0
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.HelloResponse{
				Msg: fmt.Sprintf("hello! from grpc. cnt:%d", cnt),
			})
		}
		if err != nil {
			return err
		}
		cnt++
	}
}
func (s *server) HelloBDS(stream pb.HelloService_HelloBDSServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&pb.HelloResponse{Msg: req.Msg}); err != nil {
			return nil
		}
	}
}

func main() {
	l, err := net.Listen("tcp4", ":8882")
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer()
	pb.RegisterHelloServiceServer(s, &server{})

	if err := s.Serve(l); err != nil {
		panic(err)
	}
}
