package certbot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"

	"github.com/cellebyte/go-ddns/internal/config"
	"github.com/libdns/libdns"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func AddPrefixToSlice(prefix string, slice []string) []string {
	// Pre-allocate memory to prevent slice reallocations
	newSlice := make([]string, len(slice))

	for i, element := range slice {
		newSlice[i] = prefix + element
	}
	return newSlice
}

func AbsoluteDNSNames(zone string, domains []string) []string {
	newSlice := make([]string, len(domains))

	for i, domain := range domains {
		newSlice[i] = libdns.AbsoluteName(domain, zone)
	}
	return newSlice
}

func getFileName(name, suffix string) string {
	return fmt.Sprintf("%s.%s", name, suffix)
}

func CertChallenge(dyndns config.DynDNS) error {
	config, err := ParseACMEConfig()
	if err != nil {
		return fmt.Errorf("building config: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	emails := AddPrefixToSlice("mailto:", config.MailAddresses)
	cache := autocert.DirCache(config.CacheDir)
	accountKey, err := loadAccountKey(ctx, cache)
	if err != nil {
		return err
	}
	// 2. Initialize the ACME Client
	client := &acme.Client{
		DirectoryURL: config.ACMEURL,
		Key:          accountKey,
	}

	// 3. Reuse the account associated with the cached key, or register a new one.
	account, err := ensureAccount(ctx, client, emails)
	if err != nil {
		return err
	}
	log.Printf("ACME account URI: %s", account.URI)

	// 4. Create a New Certificate Order
	domains := AbsoluteDNSNames(dyndns.Zone, []string{dyndns.RecordName})
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return fmt.Errorf("creating order: %w", err)
	}

	// 5. Process Authorizations
	for _, authURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return fmt.Errorf("getting authorization: %w", err)
		}

		// Skip if already valid
		if authz.Status == acme.StatusValid {
			continue
		}

		// Find the dns-01 challenge
		var dnsChal *acme.Challenge
		for _, chal := range authz.Challenges {
			if chal.Type == "dns-01" {
				dnsChal = chal
				break
			}
		}

		if dnsChal == nil {
			return fmt.Errorf("finding dns-01 challenge for authorization")
		}

		// 6. Generate the TXT Record Value
		// Record Name must be: _://example.com
		txtValue, err := client.DNS01ChallengeRecord(dnsChal.Token)
		if err != nil {
			return fmt.Errorf("generating TXT value: %w", err)
		}
		auth(dyndns, authz.Identifier.Value, txtValue)

		// 7. Tell the ACME server to verify the challenge
		if _, err := client.Accept(ctx, dnsChal); err != nil {
			return fmt.Errorf("accepting challenge: %w", err)
		}

		// 8. Wait for the individual authorization to become valid
		_, err = client.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return fmt.Errorf("failing authorization: %w", err)
		}
		log.Println("Domain authorization successful!")

		cleanup(dyndns, authz.Identifier.Value, txtValue)
	}

	// 9. Finalize the Order with a Certificate Signing Request (CSR)
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating certificate private key: %w", err)
	}

	err = cache.Put(ctx, getFileName(domains[0], "key.pem"), x509.MarshalPKCS1PrivateKey(certKey))
	if err != nil {
		return fmt.Errorf("caching key.pem for %s: %w", domains[0], err)
	}
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		return fmt.Errorf("creating CSR: %w", err)
	}
	err = cache.Put(ctx, getFileName(domains[0], "csr.pem"), csr)
	if err != nil {
		return fmt.Errorf("caching csr.pem for %s: %w", domains[0], err)
	}
	// // Wait for the overall order state to change to Ready, then Finalize
	// order, err = client.WaitOrder(ctx, order.URI)
	// if err != nil {
	// 	log.Fatalf("Order error before finalization: %v", err)
	// }
	derChain, certUrl, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("creating and ordering cert: %w", err)
	}
	err = cache.Put(ctx, getFileName(domains[0], "url"), []byte(certUrl))
	if err != nil {
		return fmt.Errorf("caching url for %s: %w", domains[0], err)
	}
	derChainToBuf, err := DERChainToSingleBuffer(derChain)
	if err != nil {
		return fmt.Errorf("packing chain: %w", err)
	}
	err = cache.Put(ctx, getFileName(domains[0], "crt.pem"), derChainToBuf)
	if err != nil {
		return fmt.Errorf("caching crt.pem for %s: %w", domains[0], err)
	}
	return nil
}

func ensureAccount(ctx context.Context, client *acme.Client, emails []string) (*acme.Account, error) {
	account, err := client.GetReg(ctx, "")
	if err == nil {
		return account, nil
	}
	if !errors.Is(err, acme.ErrNoAccount) {
		return nil, fmt.Errorf("looking up account: %w", err)
	}

	account, err = client.Register(ctx, &acme.Account{Contact: emails}, acme.AcceptTOS)
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		// Another process may have registered this key after our lookup.
		account, err = client.GetReg(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("looking up existing account: %w", err)
		}
		return account, nil
	}
	if err != nil {
		return nil, fmt.Errorf("registering account: %w", err)
	}
	return account, nil
}

func loadAccountKey(ctx context.Context, cache autocert.Cache) (*rsa.PrivateKey, error) {
	accountKeyBytes, err := cache.Get(ctx, defaultAccountKeyName)
	if err != nil {
		if !errors.Is(err, autocert.ErrCacheMiss) {
			return nil, fmt.Errorf("reading account key from cache: %w", err)
		}
		accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generating account.key: %w", err)
		}
		accountKeyBytes = x509.MarshalPKCS1PrivateKey(accountKey)
		if err := cache.Put(ctx, defaultAccountKeyName, accountKeyBytes); err != nil {
			return nil, fmt.Errorf("caching account.key: %w", err)
		}
	}
	accountKey, err := x509.ParsePKCS1PrivateKey(accountKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}
	return accountKey, nil
}
