package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"os"

	"github.com/jaztec/microservice-example/ca"

	"google.golang.org/grpc/credentials"

	"google.golang.org/grpc"

	"github.com/jaztec/microservice-example/proto"
)

type Server struct {
	proto.UnimplementedClientServiceServer
}

func (s *Server) ClientByID(_ context.Context, req *proto.ClientByIDRequest) (*proto.ClientByIDResponse, error) {
	log.Printf("Fetching client for ID '%s'", req.Id)
	return &proto.ClientByIDResponse{
		Client: &proto.Client{
			Id:        req.Id,
			CreatedAt: nil,
			UpdatedAt: nil,
			DeletedAt: nil,
			ExpiredAt: 0,
			Code:      "",
			Secret:    "42",
			Domain:    "http://localhost:9096",
			UserID:    "",
			Access:    "",
			Refresh:   "",
			Data:      "",
		},
	}, nil
}

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		panic("No valid LISTEN_ADDR received")
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}

	caClient, err := ca.NewCAClient("client_service")
	if err != nil {
		panic(err)
	}

	certPool, err := caClient.CertPool(context.Background(), "client_service")
	if err != nil {
		panic(err)
	}
	cert, _, err := caClient.Certificate(context.Background(), "client_service", ca.Host)
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	proto.RegisterClientServiceServer(grpcServer, &Server{})
	log.Fatal(grpcServer.Serve(lis))
}
