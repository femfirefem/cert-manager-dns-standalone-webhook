package main

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	acmetest "github.com/cert-manager/cert-manager/test/acme"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
	port = os.Getenv("PORT")
)

func TestRunsSuite(t *testing.T) {
	if len(zone) == 0 {
		zone = "example.com."
	}
	if len(port) == 0 {
		port = "59351"
	}
	solver := New(port)
	fixture := acmetest.NewFixture(solver,
		acmetest.SetResolvedZone(zone),
		//acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath("testdata/dns-standalone-solver"),
		//acmetest.SetBinariesPath("_test/kubebuilder/bin"),
		acmetest.SetDNSServer("127.0.0.1:"+port),
		acmetest.SetUseAuthoritative(false),
	)
	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}

func TestExampleSolver_Name(t *testing.T) {
	port, _ := rand.Int(rand.Reader, big.NewInt(50000))
	port = port.Add(port, big.NewInt(15534))
	solver := New(port.String())
	assert.Equal(t, "dns-standalone", solver.Name())
}

func TestExampleSolver_Initialize(t *testing.T) {
	port, _ := rand.Int(rand.Reader, big.NewInt(50000))
	port = port.Add(port, big.NewInt(15534))
	solver := New(port.String())
	done := make(chan struct{})
	err := solver.Initialize(nil, done)
	assert.NoError(t, err, "Expected Initialize not to error")
	close(done)
}

func TestExampleSolver_Present_Cleanup(t *testing.T) {
	port, _ := rand.Int(rand.Reader, big.NewInt(50000))
	port = port.Add(port, big.NewInt(15534))
	solver := New(port.String())
	done := make(chan struct{})
	err := solver.Initialize(nil, done)
	assert.NoError(t, err, "Expected Initialize not to error")

	validTestData := []struct {
		hostname string
		record   string
	}{
		{"test1.example.com.", "testkey1"},
		{"test2.example.com.", "testkey2"},
		{"test3.example.com.", "testkey3"},
	}
	for _, test := range validTestData {
		err := solver.Present(&acme.ChallengeRequest{
			Action:       acme.ChallengeActionPresent,
			Type:         "dns-01",
			ResolvedFQDN: test.hostname,
			Key:          test.record,
		})
		assert.NoError(t, err, "Unexpected error while presenting %v", t)
	}

	// Resolve test data
	for _, test := range validTestData {
		msg := new(dns.Msg)
		msg.Id = dns.Id()
		msg.RecursionDesired = true
		msg.Question = make([]dns.Question, 1)
		msg.Question[0] = dns.Question{
			Name:   dns.Fqdn(test.hostname),
			Qtype:  dns.TypeTXT,
			Qclass: dns.ClassINET,
		}
		in, err := dns.Exchange(msg, "127.0.0.1:"+port.String())

		assert.NoError(t, err, "Presented record %s not resolvable", test.hostname)
		assert.Len(t, in.Answer, 1, "RR response is of incorrect length")
		assert.Equal(t, []string{test.record}, in.Answer[0].(*dns.TXT).Txt, "TXT record returned did not match presented record")
	}

	// Cleanup test data
	for _, test := range validTestData {
		err := solver.CleanUp(&acme.ChallengeRequest{
			Action:       acme.ChallengeActionCleanUp,
			Type:         "dns-01",
			ResolvedFQDN: test.hostname,
			Key:          test.record,
		})
		assert.NoError(t, err, "Unexpected error while cleaning up %v", t)
	}

	// Resolve test data
	for _, test := range validTestData {
		msg := new(dns.Msg)
		msg.Id = dns.Id()
		msg.RecursionDesired = true
		msg.Question = make([]dns.Question, 1)
		msg.Question[0] = dns.Question{
			Name:   dns.Fqdn(test.hostname),
			Qtype:  dns.TypeTXT,
			Qclass: dns.ClassINET,
		}
		in, err := dns.Exchange(msg, "127.0.0.1:"+port.String())

		assert.NoError(t, err, "Presented record %s not resolvable", test.hostname)
		assert.Len(t, in.Answer, 0, "RR response is of incorrect length")
		assert.Equal(t, dns.RcodeNameError, in.Rcode, "Expexted NXDOMAIN")
	}

	close(done)
}
