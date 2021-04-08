package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/jaztec/microservice-example/proto"

	"github.com/jaztec/microservice-example/ca"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	userId   = "this-is-my-id"
	username = "test"
)

var (
	defaultResponse = &proto.UserResponse{
		User: &proto.User{
			UserID:   userId,
			Username: username,
		},
	}

	defaultErrorResponse = &proto.UserResponse{
		Error: &proto.Error{
			Code:    1,
			Message: "User not found",
		},
	}
)

type userManager struct {
	proto.UnimplementedUserServiceServer
}

func (m *userManager) UserByID(_ context.Context, req *proto.UserByIdRequest) (*proto.UserResponse, error) {
	if userId != req.Id {
		return defaultErrorResponse, nil
	}

	return defaultResponse, nil
}

func (m *userManager) UserByUsernamePassword(_ context.Context, req *proto.UsernamePasswordRequest) (*proto.UserResponse, error) {
	password, err := bcrypt.GenerateFromPassword([]byte(username), 8)
	if err != nil {
		return nil, err
	}

	if req.Username != username {
		log.Printf("Failed to assess %s is %s", req.Username, username)
		return defaultErrorResponse, nil
	}

	if err := bcrypt.CompareHashAndPassword(password, []byte(req.Password)); err != nil {
		// we use username as password in this example
		log.Print("Invalid password")
		return defaultErrorResponse, nil
	}

	return defaultResponse, nil
}

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

	manager := &userManager{}
	proto.RegisterUserServiceServer(grpcServer, manager)
	log.Fatal(grpcServer.Serve(lis))
}
