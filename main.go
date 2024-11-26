package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/miekg/dns"
	"k8s.io/client-go/rest"
)

var GroupName = os.Getenv("GROUP_NAME")

// Externally resolvable hostname pointing to our dns server (must reach us on port 53)
var ExternalServerAddress = strings.Trim(os.Getenv("EXTERNAL_SERVER_ADDRESS"), ".") + "."
var AcmeServerAddress = strings.Trim(os.Getenv("ACME_NS_ROOT_ADDRESS"), ".") + "."
var HostmasterEmailAddress = os.Getenv("HOSTMASTER_EMAIL_ADDRESS")

var Port = os.Getenv("PORT")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	if len(Port) == 0 {
		Port = "53"
	}
	var solver = New(Port)

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName, solver)
}

type dnsStandaloneSolver struct {
	server     *dns.Server
	txtRecords map[string]string
	sync.RWMutex
}

func (e *dnsStandaloneSolver) Name() string {
	return "dns-standalone"
}

func (e *dnsStandaloneSolver) Present(ch *acme.ChallengeRequest) error {
	e.Lock()
	e.txtRecords[ch.ResolvedFQDN] = ch.Key
	e.Unlock()
	fmt.Fprintf(os.Stdout, "Presenting %s\n", ch.ResolvedFQDN)
	return nil
}

func (e *dnsStandaloneSolver) CleanUp(ch *acme.ChallengeRequest) error {
	e.Lock()
	delete(e.txtRecords, ch.ResolvedFQDN)
	e.Unlock()
	fmt.Fprintf(os.Stdout, "Cleaned up %s\n", ch.ResolvedFQDN)
	return nil
}

func (e *dnsStandaloneSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	go func(done <-chan struct{}) {
		<-done
		if err := e.server.Shutdown(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		}
	}(stopCh)
	go func() {
		if err := e.server.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
	}()
	return nil
}

func New(port string) webhook.Solver {
	e := &dnsStandaloneSolver{
		txtRecords: make(map[string]string),
	}
	e.server = &dns.Server{
		Addr:    ":" + port,
		Net:     "udp",
		Handler: dns.HandlerFunc(e.handleDNSRequest),
	}
	return e
}

func (e *dnsStandaloneSolver) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	var anyWasFound = false
	switch req.Opcode {
	case dns.OpcodeQuery:
		for _, q := range msg.Question {
			fmt.Fprintf(os.Stdout, "Received DNS query: %s\n", q.String())
			var lowerQName = strings.ToLower(q.Name)
			isAcmeChallenge := strings.HasPrefix(lowerQName, "_acme-challenge.")
			// Check CNAME forwarded lookups
			if !isAcmeChallenge && strings.HasSuffix(lowerQName, "."+ExternalServerAddress) {
				lowerQName = "_acme-challenge." + strings.TrimSuffix(lowerQName, "."+ExternalServerAddress)
			}
			// Check NS/SOA forwarded lookups for acme root
			var isAcmeRootNsOrSoa = !isAcmeChallenge && strings.HasSuffix(lowerQName, "."+AcmeServerAddress) &&
				(q.Qtype == dns.TypeNS || q.Qtype == dns.TypeSOA)
			// Check CNAME lookup of acme subdomain
			var isAcmeSubdomainCName = false
			if isAcmeChallenge && strings.HasSuffix(lowerQName, "."+AcmeServerAddress) && q.Qtype == dns.TypeCNAME {
				lowerQName = "_acme-challenge." + strings.TrimSuffix(lowerQName, "."+AcmeServerAddress)
				isAcmeSubdomainCName = true
			}
			e.RLock()
			record, found := e.txtRecords[lowerQName]
			e.RUnlock()
			msg.Authoritative = found && isAcmeChallenge
			if isAcmeChallenge || isAcmeRootNsOrSoa || isAcmeSubdomainCName {
				anyWasFound = true
				if q.Qtype == dns.TypeTXT {
					if !found {
						msg.SetRcode(req, dns.RcodeNameError)
						continue
					}
					if e.tryAppendRR(msg, req, fmt.Sprintf("%s 5 IN TXT %s", q.Name, record)) != nil {
						break
					}
				} else if q.Qtype == dns.TypeNS {
					if e.tryAppendRR(msg, req, fmt.Sprintf("%s 5 IN NS %s", q.Name, ExternalServerAddress)) != nil {
						break
					}
				} else if q.Qtype == dns.TypeSOA {
					if e.tryAppendRR(msg, req, getSoaRecord(q.Name)) != nil {
						break
					}
				} else {
					rr, err := dns.NewRR(getSoaRecord(q.Name))
					if err != nil {
						msg.SetRcode(req, dns.RcodeServerFailure)
						break
					} else {
						msg.Ns = append(msg.Ns, rr)
					}
					msg.SetRcode(req, dns.RcodeNameError)
				}
			} else {
				msg.SetRcode(req, dns.RcodeNameError)
			}
		}
	}
	if anyWasFound {
		w.WriteMsg(msg)
	}
}

func getSoaRecord(name string) string {
	var rname = strings.Replace(HostmasterEmailAddress, "@", ".", 1)
	if len(HostmasterEmailAddress) == 0 {
		HostmasterEmailAddress = strings.TrimSuffix(ExternalServerAddress, ".")
	}
	// name ttl recordtype mname rname serial refresh retry expire ttl
	return fmt.Sprintf("%s 5 IN SOA %s %s %d %d %d %d %d",
		name, ExternalServerAddress, rname, time.Now().Unix(), 5, 5, 1209600, 5)
}

func (e *dnsStandaloneSolver) tryAppendRR(msg *dns.Msg, req *dns.Msg, s string) error {
	rr, err := dns.NewRR(s)
	if err != nil {
		msg.SetRcode(req, dns.RcodeServerFailure)
		return err
	} else {
		msg.Answer = append(msg.Answer, rr)
		return nil
	}
}
