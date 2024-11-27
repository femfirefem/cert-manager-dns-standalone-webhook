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
var AuthorativeZoneName = strings.Trim(os.Getenv("AUTHORATIVE_ZONE_NAME"), ".") + "."
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
			isUnderAuthorative := strings.HasSuffix(lowerQName, "."+AuthorativeZoneName)
			isAuthorativeZone := lowerQName == AuthorativeZoneName
			isAuthorativeNsOrSoa := !isAcmeChallenge && (isUnderAuthorative || isAuthorativeZone) && (q.Qtype == dns.TypeNS || q.Qtype == dns.TypeSOA)

			// Update lowerQName if under external or acme root, so it can match txtRecords
			if !isAcmeChallenge && isUnderAuthorative {
				lowerQName = "_acme-challenge." + strings.TrimSuffix(lowerQName, "."+AuthorativeZoneName) + "."
			}
			e.RLock()
			record, found := e.txtRecords[lowerQName]
			e.RUnlock()

			// Add "aa" to "flags" if acme challenge found or the request is under our authorative zone
			msg.Authoritative = found && isAcmeChallenge || isAuthorativeZone || isUnderAuthorative

			// Whether we should respond at all to this request or not
			if found && isAcmeChallenge || isUnderAuthorative || isAuthorativeZone {
				anyWasFound = true
				// If not NS or SOA, and not found in txtRecords, set name error and continue
				if !isAuthorativeNsOrSoa && !isAuthorativeZone && !found {
					msg.SetRcode(req, dns.RcodeNameError)
					continue
				}

				var responseRecord = getSoaRecord()
				if q.Qtype == dns.TypeNS && isAuthorativeZone {
					responseRecord = getNsRecord()
				} else if found && q.Qtype == dns.TypeTXT {
					responseRecord = fmt.Sprintf("%s 5 IN TXT %s", q.Name, record)
				} else if !found && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) {
					msg.SetRcode(req, dns.RcodeFormatError)
				}

				if (isAcmeChallenge || isUnderAuthorative) && found || isAuthorativeZone {
					if e.tryAppendAnswer(msg, req, responseRecord) != nil {
						break
					}
				} else if isUnderAuthorative {
					if e.tryAppendNs(msg, req, responseRecord) != nil {
						break
					}
				} else {
					// Should not end up here
					msg.SetRcode(req, dns.RcodeServerFailure)
					break
				}

				msg.SetRcode(req, dns.RcodeSuccess)
			} else {
				msg.SetRcode(req, dns.RcodeNameError)
			}
		}
	}
	if anyWasFound {
		w.WriteMsg(msg)
	}
}

func getNsRecord() string {
	return fmt.Sprintf("%s 5 IN NS %s", AuthorativeZoneName, ExternalServerAddress)
}

func getSoaRecord() string {
	var rname = strings.Replace(HostmasterEmailAddress, "@", ".", 1)
	// name ttl recordtype mname rname serial refresh retry expire ttl
	return fmt.Sprintf("%s 5 IN SOA %s %s %d %d %d %d %d",
		AuthorativeZoneName, ExternalServerAddress, rname, time.Now().Unix(), 5, 5, 1209600, 5)
}

func (e *dnsStandaloneSolver) tryAppendAnswer(msg *dns.Msg, req *dns.Msg, s string) error {
	rr, err := dns.NewRR(s)
	if err != nil {
		msg.SetRcode(req, dns.RcodeServerFailure)
		return err
	} else {
		msg.Answer = append(msg.Answer, rr)
		return nil
	}
}

func (e *dnsStandaloneSolver) tryAppendNs(msg *dns.Msg, req *dns.Msg, s string) error {
	rr, err := dns.NewRR(s)
	if err != nil {
		msg.SetRcode(req, dns.RcodeServerFailure)
		return err
	} else {
		msg.Ns = append(msg.Ns, rr)
		return nil
	}
}
