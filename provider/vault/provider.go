package vault

import (
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/ty/fun"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/provider"
	"github.com/containous/traefik/rules"
	"github.com/containous/traefik/safe"
	traefiktls "github.com/containous/traefik/tls"
	"github.com/containous/traefik/types"
)

// Configuration holds ACME configuration provided by users
type Configuration struct {
	Email       string         `description:"Email address used for registration"`
	ACMELogging bool           `description:"Enable debug logging of ACME actions."`
	CAServer    string         `description:"CA server to use."`
	Storage     string         `description:"Storage to use."`
	EntryPoint  string         `description:"EntryPoint to use."`
	KeyType     string         `description:"KeyType used for generating certificate private key. Allow value 'EC256', 'EC384', 'RSA2048', 'RSA4096', 'RSA8192'. Default to 'RSA4096'"`
	OnHostRule  bool           `description:"Enable certificate generation on frontends Host rules."`
	Domains     []types.Domain `description:"CN and SANs (alternative domains) to each main domain using format: --acme.domains='main.com,san1.com,san2.com' --acme.domains='*.main.net'. No SANs for wildcards domain. Wildcard domains only accepted with DNSChallenge"`
}

// Certificate is a struct which contains all data needed from a TLS certificate
type Certificate struct {
	Domain      types.Domain
	Certificate []byte
	Key         []byte
}

// Provider holds configurations of the provider.
type Provider struct {
	*Configuration
	*provider.BaseProvider
	certificates           []*Certificate
	certsChan              chan *Certificate
	configurationChan      chan<- types.ConfigMessage
	certificateStore       *traefiktls.CertificateStore
	clientMutex            sync.Mutex
	configFromListenerChan chan types.Configuration
	pool                   *safe.Pool
}

// Init for compatibility reason the BaseProvider implements an empty Init
func (p *Provider) Init(_ types.Constraints) error {
	return nil
}

func (p *Provider) Provide(configurationChan chan<- types.ConfigMessage, pool *safe.Pool) error {
	p.pool = pool

	// provide updates to traefik when certs change
	p.watchCertificate()

	// only watch for new domains if the onHostRule is set to true
	if p.OnHostRule {
		p.watchNewDomains()
	}

	p.configurationChan = configurationChan
	//p.refreshCertificates()

	// deduplicate domain list
	p.Domains = deleteUnnecessaryDomains(p.Domains)

	for i := 0; i < len(p.Domains); i++ {
		domain := p.Domains[i]
		safe.Go(func() {
			if _, err := p.resolveCertificate(domain, true); err != nil {
				log.Errorf("Unable to obtain ACME certificate for domains %q : %v", strings.Join(domain.ToStrArray(), ","), err)
			}
		})
	}

	ticker := time.NewTicker(24 * time.Hour)
	pool.Go(func(stop chan bool) {
		for {
			select {
			case <-ticker.C:
				p.renewCertificates()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	})
}

// obtainCertificate gets a cert for the given domain and adds it to the providers
// certificate array
func (p *Provider) obtainCertificate(domain types.Domain) error {
	domains := fun.Map(types.CanonicalDomain, domain.ToStrArray()).([]string)

	// Check provided certificates
	uncheckedDomains := p.getUncheckedDomains(domains, !domainFromConfigurationFile)
	if len(uncheckedDomains) == 0 {
		return nil, nil
	}

	log.Debugf("Loading vault certificates %+v...", uncheckedDomains)

	// TODO get from vault

	log.Debugf("Certificates obtained for domains %+v", uncheckedDomains)

	if len(uncheckedDomains) > 1 {
		domain = types.Domain{Main: uncheckedDomains[0], SANs: uncheckedDomains[1:]}
	} else {
		domain = types.Domain{Main: uncheckedDomains[0]}
	}
	p.addCertificateForDomain(domain, certificate.Certificate, certificate.PrivateKey)

	return certificate, nil
}

// watchNewDomains watches for incoming Frontend config changes
func (p *Provider) watchNewDomains() {
	p.pool.Go(func(stop chan bool) {
		for {
			select {
			case config := <-p.configFromListenerChan:
				for _, frontend := range config.Frontends {
					for _, route := range frontend.Routes {
						domainRules := rules.Rules{}
						domains, err := domainRules.ParseDomains(route.Rule)
						if err != nil {
							log.Errorf("Error parsing domains in provider vault: %v", err)
							continue
						}

						if len(domains) == 0 {
							log.Debugf("No domain parsed in rule %q", route.Rule)
							continue
						}

						log.Debugf("Try to challenge certificate for domain %v founded in Host rule", domains)

						var domain types.Domain
						if len(domains) > 0 {
							domain = types.Domain{Main: domains[0]}
							if len(domains) > 1 {
								domain.SANs = domains[1:]
							}

							// Try to get a cert asyncn
							safe.Go(func() {
								if _, err := p.resolveCertificate(domain, false); err != nil {
									log.Errorf("Unable to obtain ACME certificate for domains %q detected thanks to rule %q : %v", strings.Join(domains, ","), route.Rule, err)
								}
							})
						}
					}
				}
			case <-stop:
				return
			}
		}
	})
}

// watchCertificate watches on the certs chan for new or updates certs,
// updates the p.certificates array, and then calls for traefik config updates
func (p *Provider) watchCertificate() {
	p.certsChan = make(chan *Certificate)
	p.pool.Go(func(stop chan bool) {
		for {
			select {
			case cert := <-p.certsChan:
				certUpdated := false
				for _, domainsCertificate := range p.certificates {
					if reflect.DeepEqual(cert.Domain, domainsCertificate.Domain) {
						domainsCertificate.Certificate = cert.Certificate
						domainsCertificate.Key = cert.Key
						certUpdated = true
						break
					}
				}
				if !certUpdated {
					p.certificates = append(p.certificates, cert)
				}

				p.refreshCertificates()

			case <-stop:
				return
			}
		}
	})
}

// refreshCertificates sends a config message to traefik with the updated TLS certs
func (p *Provider) refreshCertificates() {
	config := types.ConfigMessage{
		ProviderName: "vault",
		Configuration: &types.Configuration{
			Backends:  map[string]*types.Backend{},
			Frontends: map[string]*types.Frontend{},
			TLS:       []*traefiktls.Configuration{},
		},
	}

	for _, cert := range p.certificates {
		certificate := &traefiktls.Certificate{CertFile: traefiktls.FileOrContent(cert.Certificate), KeyFile: traefiktls.FileOrContent(cert.Key)}
		config.Configuration.TLS = append(config.Configuration.TLS, &traefiktls.Configuration{Certificate: certificate, EntryPoints: []string{p.EntryPoint}})
	}
	p.configurationChan <- config
}

// deleteUnnecessaryDomains deletes from the configuration :
// - Duplicated domains
// - Domains which are checked by wildcard domain
func deleteUnnecessaryDomains(allDomains []types.Domain) []types.Domain {
	var newDomains []types.Domain

	for idxDomainToCheck, domainToCheck := range allDomains {
		keepDomain := true

		for idxDomain, domain := range allDomains {
			if idxDomainToCheck == idxDomain {
				continue
			}

			if reflect.DeepEqual(domain, domainToCheck) {
				if idxDomainToCheck > idxDomain {
					log.Warnf("The domain %v is duplicated in the configuration but will be processed by ACME provider only once.", domainToCheck)
					keepDomain = false
				}
				break
			}

			// Check if CN or SANS to check already exists
			// or can not be checked by a wildcard
			var newDomainsToCheck []string
			for _, domainProcessed := range domainToCheck.ToStrArray() {
				if idxDomain < idxDomainToCheck && isDomainAlreadyChecked(domainProcessed, domain.ToStrArray()) {
					// The domain is duplicated in a CN
					log.Warnf("Domain %q is duplicated in the configuration or validated by the domain %v. It will be processed once.", domainProcessed, domain)
					continue
				} else if domain.Main != domainProcessed && strings.HasPrefix(domain.Main, "*") && isDomainAlreadyChecked(domainProcessed, []string{domain.Main}) {
					// Check if a wildcard can validate the domain
					log.Warnf("Domain %q will not be processed by ACME provider because it is validated by the wildcard %q", domainProcessed, domain.Main)
					continue
				}
				newDomainsToCheck = append(newDomainsToCheck, domainProcessed)
			}

			// Delete the domain if both Main and SANs can be validated by the wildcard domain
			// otherwise keep the unchecked values
			if newDomainsToCheck == nil {
				keepDomain = false
				break
			}
			domainToCheck.Set(newDomainsToCheck)
		}

		if keepDomain {
			newDomains = append(newDomains, domainToCheck)
		}
	}

	return newDomains
}

func isDomainAlreadyChecked(domainToCheck string, existentDomains []string) bool {
	for _, certDomains := range existentDomains {
		for _, certDomain := range strings.Split(certDomains, ",") {
			if types.MatchDomain(domainToCheck, certDomain) {
				return true
			}
		}
	}
	return false
}

// Get provided certificate which check a domains list (Main and SANs)
// from static and dynamic provided certificates
func (p *Provider) getUncheckedDomains(domainsToCheck []string, checkConfigurationDomains bool) []string {
	log.Debugf("Looking for provided certificate(s) to validate %q...", domainsToCheck)

	allDomains := p.certificateStore.GetAllDomains()

	// Get ACME certificates
	for _, certificate := range p.certificates {
		allDomains = append(allDomains, strings.Join(certificate.Domain.ToStrArray(), ","))
	}

	// Get Configuration Domains
	if checkConfigurationDomains {
		for i := 0; i < len(p.Domains); i++ {
			allDomains = append(allDomains, strings.Join(p.Domains[i].ToStrArray(), ","))
		}
	}

	// return searchUncheckedDomains(domainsToCheck, allDomains)
	// inlined below
	var uncheckedDomains []string
	for _, domainToCheck := range domainsToCheck {
		if !isDomainAlreadyChecked(domainToCheck, existentDomains) {
			uncheckedDomains = append(uncheckedDomains, domainToCheck)
		}
	}

	if len(uncheckedDomains) == 0 {
		log.Debugf("No ACME certificate to generate for domains %q.", domainsToCheck)
	} else {
		log.Debugf("Domains %q need ACME certificates generation for domains %q.", domainsToCheck, strings.Join(uncheckedDomains, ","))
	}
	return uncheckedDomains
}
