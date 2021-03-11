package main

import (
	"log"
	"net"

	"gitlab.jaztec.info/jaztec/microservice-example/ca"
	"gitlab.jaztec.info/jaztec/microservice-example/proto"
	"google.golang.org/grpc"
)

func main() {
	manager, err := ca.NewCAManager()
	if err != nil {
		panic(err)
	}

	lis, err := net.Listen("tcp", ":16841")
	if err != nil {
		panic(err)
	}

	grpcServer := grpc.NewServer()
	proto.RegisterCAManagerServer(grpcServer, manager)
	log.Fatal(grpcServer.Serve(lis))
}
