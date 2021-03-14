package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"

	"gitlab.jaztec.info/jaztec/microservice-example/ca"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	microservice_example "gitlab.jaztec.info/jaztec/microservice-example"

	"github.com/go-oauth2/oauth2/v4"
	"gitlab.jaztec.info/jaztec/microservice-example/proto"
)

type Store struct {
	addr     string
	caClient *ca.CAClient
	client   proto.ClientServiceClient
	conn     *grpc.ClientConn
}

// TODO Implement some real storage
func (s *Store) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	log.Printf("Fetching client with ID '%s'", id)

	resp, err := s.client.ClientByID(ctx, &proto.ClientByIDRequest{Id: id})
	if err != nil {
		return nil, fmt.Errorf("error fetching client: %w", err)
	}
	if resp.Error != nil {
		return nil, errors.New(resp.Error.Message)
	}

	return &microservice_example.Client{
		ID:        resp.Client.Id,
		ExpiredAt: resp.Client.ExpiredAt,
		Code:      resp.Client.Code,
		Secret:    resp.Client.Secret,
		Domain:    resp.Client.Domain,
		UserID:    resp.Client.UserID,
		Access:    resp.Client.Access,
		Refresh:   resp.Client.Refresh,
		Data:      resp.Client.Data,
	}, nil
}

func (s *Store) Close() error {
	log.Println("Closing store connection")
	return s.conn.Close()
}

func NewStore(addr string) (*Store, error) {
	caClient, err := ca.NewCAClient()
	if err != nil {
		return nil, err
	}

	certPool, err := caClient.CertPool(context.Background(), "auth_service")
	if err != nil {
		return nil, err
	}

	crt, _, err := caClient.Certificate(context.Background(), "auth_service", ca.Client)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{crt},
	}

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("error dialing %s, got error: %w", addr, err)
	}

	return &Store{
		addr:     addr,
		caClient: caClient,
		client:   proto.NewClientServiceClient(conn),
		conn:     conn,
	}, nil
}
