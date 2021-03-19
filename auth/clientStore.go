package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	microservice_example "gitlab.jaztec.info/jaztec/microservice-example"

	"github.com/go-oauth2/oauth2/v4"
	"gitlab.jaztec.info/jaztec/microservice-example/proto"
)

type Store struct {
	addr   string
	client proto.ClientServiceClient
	conn   *grpc.ClientConn
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

func NewStore(addr string, tlsConfig *tls.Config) (*Store, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("error dialing %s, got error: %w", addr, err)
	}

	return &Store{
		addr:   addr,
		client: proto.NewClientServiceClient(conn),
		conn:   conn,
	}, nil
}
