package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"google.golang.org/grpc/credentials"

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

func (c *CAClient) init(cert tls.Certificate) error {
	conn, err := grpc.Dial(
		"ca_service:16841",
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		})),
	)
	if err != nil {
		return fmt.Errorf("error while dailing ca_service: %w", err)
	}
	c.conn = conn

	return nil
}

func (c *CAClient) Close() error {
	return c.conn.Close()
}

func NewCAClient(host string) (*CAClient, error) {
	c := &CAClient{}

	crt, err := clientCertificate(host)
	if err != nil {
		return nil, err
	}

	if err := c.init(*crt); err != nil {
		return nil, err
	}
	return c, nil
}

func clientCertificate(host string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{host},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:    x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	crt, _, err := createCert(&template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("cert creation failed: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{crt.Raw},
	}, nil
}
