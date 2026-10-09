package certbot

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cellebyte/go-ddns/internal/config"
	"github.com/cellebyte/go-ddns/internal/doh"
	"github.com/libdns/libdns"
	"github.com/sethvargo/go-retry"
	"golang.org/x/net/dns/dnsmessage"
)

func GetChallengeRecordName(identifier, zone string) string {
	return libdns.RelativeName(fmt.Sprintf("%s.%s", ACMETXTPrefix, identifier), zone)
}

func Hook(config config.DynDNS, identifier, challenge string, cleanup bool) error {
	ctx := context.Background()
	var propagationTimeout time.Duration
	if !cleanup {
		cfg, err := ParseACMEConfig()
		if err != nil {
			return fmt.Errorf("building ACME config: %w", err)
		}
		propagationTimeout = cfg.TXTPropagationTimeout
	}
	dohClient, err := doh.NewClient(config.DOHProvider.String(), config.DOHProvider.Endpoint())
	if err != nil {
		return fmt.Errorf("creating doh client for %v+: %w", config.DOHProvider, err)
	}
	dnsProviderClient, err := config.Provider.New(config.APIToken)
	if err != nil {
		return fmt.Errorf("instantiating client: %w", err)
	}
	if cleanup {
		records, err := dnsProviderClient.GetRecords(ctx, config.Zone)
		if err != nil {
			return fmt.Errorf("getting Records: %w", err)
		}
		name := GetChallengeRecordName(identifier, config.Zone)
		var toDelete []libdns.Record
		for _, record := range records {
			if record.RR().Name == name {
				toDelete = append(toDelete, record)
			}
		}
		deleted, err := dnsProviderClient.DeleteRecords(ctx, config.Zone, toDelete)
		if err != nil {
			return fmt.Errorf("deleting [%v] only deleted [%v]: %w", toDelete, deleted, err)
		}
		return nil
	}
	// ACME DNS-01 challenge
	txtRecord := libdns.TXT{
		Name: GetChallengeRecordName(identifier, config.Zone),
		TTL:  time.Duration(600 * time.Second),
		Text: challenge,
	}
	updated, err := dnsProviderClient.SetRecords(ctx, config.Zone, []libdns.Record{txtRecord})
	if err != nil {
		return fmt.Errorf("creating %v only created [%v]: %w", txtRecord, updated, err)
	}
	// Check DNS for existence
	fullName := libdns.AbsoluteName(txtRecord.Name, config.Zone)

	return waitForTXT(ctx, propagationTimeout, dohClient, fullName, txtRecord.Text)
}

type txtResolver interface {
	Query(string, dnsmessage.Type) ([]string, error)
}

// waitForTXT polls independently of the ACME order timeout, as DNS propagation
// can take longer than ACME's network operations. The deadline includes queries.
func waitForTXT(ctx context.Context, timeout time.Duration, client txtResolver, name, token string) error {
	return waitForTXTWithInterval(ctx, timeout, 2*time.Second, client, name, token)
}

func waitForTXTWithInterval(ctx context.Context, timeout, interval time.Duration, client txtResolver, name, token string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	attempt := 0
	err := retry.Do(ctx, retry.NewConstant(interval), func(ctx context.Context) error {
		attempt++
		responses, err := client.Query(name, dnsmessage.TypeTXT)
		if err != nil {
			lastErr = fmt.Errorf("resolving challenge for %s: %w", name, err)
			log.Printf("TXT propagation check %d for %s: resolver error (retrying)", attempt, name)
			return retry.RetryableError(lastErr)
		}
		for _, response := range responses {
			if token == strings.TrimSpace(response) {
				log.Printf("TXT propagation check %d for %s: expected record found", attempt, name)
				return nil
			}
		}
		lastErr = fmt.Errorf("finding token for %s: expected value not present (%d TXT answers)", name, len(responses))
		log.Printf("TXT propagation check %d for %s: expected record not visible (%d TXT answers; retrying)", attempt, name, len(responses))
		return retry.RetryableError(lastErr)
	})
	if err != nil {
		return fmt.Errorf("retry for existence (last result: %v): %w", lastErr, err)
	}
	return nil
}

func Auth(config config.DynDNS, params CertBotParameters) {
	auth(config, params.Identifier, params.Validation)
}

func Cleanup(config config.DynDNS, params CertBotParameters) {
	cleanup(config, params.Identifier, params.Validation)
}

func auth(config config.DynDNS, identifier, challenge string) {
	err := Hook(config, identifier, challenge, false)
	if err != nil {
		panic(fmt.Errorf("calling auth hook: %w", err))
	}
}
func cleanup(config config.DynDNS, identifier, challenge string) {
	err := Hook(config, identifier, challenge, true)
	if err != nil {
		panic(fmt.Errorf("calling cleanup hook: %w", err))
	}
}
