package ca_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gitlab.jaztec.info/jaztec/microservice-example/ca"
)

var _ = Describe("Client", func() {
	Context("Usage of CAClient", func() {
		It("Should instantiate a new instance of the CAClient", func() {
			_, err := ca.NewCAClient("test_client")
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
