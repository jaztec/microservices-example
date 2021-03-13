package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"gitlab.jaztec.info/jaztec/microservice-example/proto"
)

var ()

type Type int

const Client Type = 1
const Host Type = 2

type initFn func(*CAManager) error

func WithAllowedHosts(hosts []string) initFn {
	return func(m *CAManager) error {
		m.allowedHosts = hosts
		return nil
	}
}

func WithAllowedClients(clients []string) initFn {
	return func(m *CAManager) error {
		m.allowedClients = clients
		return nil
	}
}

type CAManager struct {
	ca      *x509.Certificate
	root    []byte
	privKey *rsa.PrivateKey

	hosts   [][]byte
	clients [][]byte

	allowedHosts   []string
	allowedClients []string
	issuedHosts    []string
	issuedClients  []string

	proto.UnimplementedCAManagerServer
}

func NewCAManager(opts ...initFn) (*CAManager, error) {
	m := &CAManager{
		allowedHosts:   []string{},
		allowedClients: []string{},
		issuedHosts:    []string{},
		issuedClients:  []string{},
	}

	for _, fn := range opts {
		if err := fn(m); err != nil {
			return nil, err
		}
	}

	ca, caPem, caPriv, err := createRootCertificate()
	if err != nil {
		return nil, err
	}
	m.ca = ca
	m.root = caPem
	m.privKey = caPriv

	return m, nil
}

func (m *CAManager) CACertificate(_ context.Context, req *proto.CertificateRequest) (*proto.CAResponse, error) {
	if !hostAllowed(req.Host, m.allowedHosts) {
		return nil, fmt.Errorf("host '%s' is not allowed", req.Host)
	}

	return &proto.CAResponse{Cert: m.root}, nil
}

func (m *CAManager) Certificate(_ context.Context, req *proto.CertificateRequest) (*proto.CertificateResponse, error) {
	crt, key, err := m.createCertificate(req.Host, Type(req.Type))
	if err != nil {
		return nil, err
	}
	return &proto.CertificateResponse{Cert: crt, Key: key}, nil
}

func (m *CAManager) ListCertificates(_ context.Context, req *proto.ListRequest) (*proto.ListResponse, error) {
	var certs [][]byte
	switch Type(req.Type) {
	case Client:
		certs = m.clients
	case Host:
		certs = m.hosts
	default:
		return nil, fmt.Errorf("host type %d not allowed", req.Type)
	}

	return &proto.ListResponse{Certs: certs}, nil
}

func (m *CAManager) createCertificate(host string, t Type) (crtPem []byte, crtKey []byte, err error) {
	log.Printf("Requested %s with type %d", host, t)
	if err = m.validate(host, t); err != nil {
		return nil, nil, fmt.Errorf("%s %d validation failed: %w", host, t, err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	var keyUsage x509.KeyUsage
	var extKeyUsage x509.ExtKeyUsage
	switch t {
	case Client:
		keyUsage |= x509.KeyUsageContentCommitment
		extKeyUsage |= x509.ExtKeyUsageClientAuth
		m.clients = append(m.clients, crtPem)
		m.issuedClients = append(m.issuedClients, host)
	case Host:
		extKeyUsage |= x509.ExtKeyUsageServerAuth
		keyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		m.hosts = append(m.hosts, crtPem)
		m.issuedHosts = append(m.issuedHosts, host)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{host},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:    keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{extKeyUsage},

		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	_, crtPem, err = createCert(&template, m.ca, &priv.PublicKey, m.privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cert creation failed: %w", err)
	}

	key := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return crtPem, key, nil
}

func createRootCertificate() (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate key")
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"NL"},
			Organization: []string{"Jaztec"},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	crt, certPem, err := createCert(&template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate key")
	}
	return crt, certPem, priv, nil
}

func createCert(template, parent *x509.Certificate, pub *rsa.PublicKey, priv *rsa.PrivateKey) (*x509.Certificate, []byte, error) {
	crtBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cert: %w", err)
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cert: %w", err)
	}

	crtPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	})

	return crt, crtPem, nil
}

func (m *CAManager) validate(host string, side Type) error {
	var allowed []string
	var issued []string
	switch side {
	case Client:
		allowed = m.allowedClients
		issued = m.issuedClients
	case Host:
		allowed = m.allowedHosts
		issued = m.issuedHosts
	}
	if !hostAllowed(host, allowed) {
		return fmt.Errorf("host '%s' is not allowed", host)
	}
	if hostIssued(host, issued) {
		return fmt.Errorf("host '%s' is already issued", host)
	}
	return nil
}

func hostAllowed(host string, soi []string) bool {
	for _, n := range soi {
		if n == host {
			return true
		}
	}
	return false
}

func hostIssued(host string, soi []string) bool {
	for _, n := range soi {
		if n == host {
			return true
		}
	}
	return false
}
