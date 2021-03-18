package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"os"

	"gitlab.jaztec.info/jaztec/microservice-example/ca"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	listenAddr := flag.String("addr", ":50051", "Set the listen address for the gRPC server")

	addr := os.Getenv("LISTEN_ADDR")
	if addr != "" {
		listenAddr = &addr
	}
	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		panic(err)
	}

	caClient, err := ca.NewCAClient("user_service")
	if err != nil {
		panic(err)
	}

	certPool, err := caClient.CertPool(context.Background(), "user_service")
	if err != nil {
		panic(err)
	}
	cert, _, err := caClient.Certificate(context.Background(), "user_service", ca.Host)
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	log.Fatal(grpcServer.Serve(lis))
}
