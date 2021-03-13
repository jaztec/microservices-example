package ca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"gitlab.jaztec.info/jaztec/microservice-example/proto"
	"google.golang.org/grpc"
)

type CAClient struct {
	conn *grpc.ClientConn
}

func (c *CAClient) CertPool(ctx context.Context, host string) (*x509.CertPool, error) {
	if c.conn == nil {
		return nil, errors.New("client connection not yet available")
	}
	client := proto.NewCAManagerClient(c.conn)
	resp, err := client.CACertificate(ctx, &proto.CertificateRequest{Host: host})
	if err != nil {
		return nil, fmt.Errorf("error fetching CA certificate: %w", err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(resp.Cert); ok != true {
		return nil, errors.New("could not append CA certs from bytes")
	}

	return pool, nil
}

func (c *CAClient) Certificate(ctx context.Context, host string, side Type) (tls.Certificate, []byte, error) {
	client := proto.NewCAManagerClient(c.conn)
	resp, err := client.Certificate(ctx, &proto.CertificateRequest{
		Host: host,
		Type: int32(side),
	})
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("error fetching CA certificate: %w", err)
	}
	crt, err := tls.X509KeyPair(resp.Cert, resp.Key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("error fetching CA certificate: %w", err)
	}
	return crt, resp.Key, nil
}

func (c *CAClient) init() error {
	conn, err := grpc.Dial("ca_service:16841", grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("error while dailing ca_service: %w", err)
	}
	c.conn = conn

	return nil
}

func (c *CAClient) Close() error {
	return c.conn.Close()
}

func NewCAClient() (*CAClient, error) {
	c := &CAClient{}
	if err := c.init(); err != nil {
		return nil, err
	}
	return c, nil
}
