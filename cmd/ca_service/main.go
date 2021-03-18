package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"

	"google.golang.org/grpc/credentials"

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

	resp, err := manager.Certificate(context.Background(), &proto.CertificateRequest{
		Host: "ca_service",
		Type: int32(ca.Host),
	})
	if err != nil {
		panic(err)
	}

	cert, err := tls.X509KeyPair(resp.Cert, resp.Key)
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
	)
	proto.RegisterCAManagerServer(grpcServer, manager)
	log.Fatal(grpcServer.Serve(lis))
}
