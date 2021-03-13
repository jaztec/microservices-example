package ca_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gitlab.jaztec.info/jaztec/microservice-example/ca"
	"gitlab.jaztec.info/jaztec/microservice-example/proto"
)

var _ = Describe("Manager", func() {
	var manager *ca.CAManager
	var caCertPool = x509.NewCertPool()
	var serverCert tls.Certificate
	var clientCert tls.Certificate

	Context("Run all procedures", func() {
		It("Should create a CAManager", func() {
			m, err := ca.NewCAManager(ca.WithAllowedHosts([]string{"test_host"}), ca.WithAllowedClients([]string{"test_client"}))
			Expect(err).ToNot(HaveOccurred())
			manager = m
		})

		It("Should generate RootCA", func() {
			resp, err := manager.CACertificate(context.Background(), &proto.CertificateRequest{
				Host: "test_host",
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(caCertPool.AppendCertsFromPEM(resp.Cert)).To(BeTrue())
		})

		It("Should generate server cert", func() {
			resp, err := manager.Certificate(context.Background(), &proto.CertificateRequest{Host: "test_host", Type: int32(ca.Host)})
			Expect(err).ToNot(HaveOccurred())

			crt, err := tls.X509KeyPair(resp.Cert, resp.Key)
			Expect(err).ToNot(HaveOccurred())
			serverCert = crt
			Expect(serverCert).To(Equal(crt))
		})

		It("Should generate client cert", func() {
			resp, err := manager.Certificate(context.Background(), &proto.CertificateRequest{Host: "test_client", Type: int32(ca.Client)})
			Expect(err).ToNot(HaveOccurred())

			crt, err := tls.X509KeyPair(resp.Cert, resp.Key)
			Expect(err).ToNot(HaveOccurred())
			clientCert = crt
			Expect(clientCert).To(Equal(crt))
		})

		It("Should setup a server communications", func(done Done) {
			c := make(chan struct{})
			lis, err := tls.Listen("tcp", ":29854", &tls.Config{
				ClientCAs:    caCertPool,
				Certificates: []tls.Certificate{serverCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
			})
			go func() {
				defer GinkgoRecover()
				conn, err := lis.Accept()
				if err != nil {
					Fail("Failed accepting")
				}
				var b []byte
				_, err = conn.Read(b)
				Expect(err).ToNot(HaveOccurred())

				c <- struct{}{}
			}()
			Expect(err).ToNot(HaveOccurred())
			defer lis.Close()

			go func() {
				defer GinkgoRecover()
				conn, err := tls.Dial("tcp", ":29854", &tls.Config{
					RootCAs:      caCertPool,
					Certificates: []tls.Certificate{clientCert},
					ServerName:   "test_host",
				})
				Expect(err).ToNot(HaveOccurred())

				n, err := conn.Write([]byte("test"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(4))

				defer conn.Close()
			}()

			Expect(<-c).To(Equal(struct{}{}))
			close(done)
		})
	})
})
