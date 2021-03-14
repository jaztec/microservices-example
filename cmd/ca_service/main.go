package main

import (
	"log"
	"net"

	"gitlab.jaztec.info/jaztec/microservice-example/ca"
	"gitlab.jaztec.info/jaztec/microservice-example/proto"
	"google.golang.org/grpc"
)

func main() {
	manager, err := ca.NewCAManager(
		ca.WithAllowedHosts([]string{"ca_service", "client_service", "auth_service", "user_service"}),
		ca.WithAllowedClients([]string{"auth_service", "jwt_token"}),
	)
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
