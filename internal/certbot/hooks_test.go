package certbot

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type delayedTXTResolver struct {
	attempts  int
	visibleAt int
}

func (r *delayedTXTResolver) Query(_ string, typ dnsmessage.Type) ([]string, error) {
	if typ != dnsmessage.TypeTXT {
		return nil, errors.New("expected TXT query")
	}
	r.attempts++
	if r.attempts >= r.visibleAt {
		return []string{"expected-token"}, nil
	}
	return nil, nil
}

func TestWaitForTXTAfterFourMisses(t *testing.T) {
	resolver := &delayedTXTResolver{visibleAt: 6}
	if err := waitForTXTWithInterval(context.Background(), time.Second, time.Millisecond, resolver, "_acme-challenge.example.org", "expected-token"); err != nil {
		t.Fatal(err)
	}
	if resolver.attempts != 6 {
		t.Fatalf("attempted %d queries; want 6", resolver.attempts)
	}
}

func TestWaitForTXTTimeout(t *testing.T) {
	resolver := &delayedTXTResolver{visibleAt: 10000}
	err := waitForTXTWithInterval(context.Background(), 15*time.Millisecond, time.Millisecond, resolver, "_acme-challenge.example.org", "expected-token")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected propagation deadline, got %v", err)
	}
}

func TestTXTPropagationTimeoutConfig(t *testing.T) {
	t.Setenv(acmeTXTPropagationTimeout, "")
	cfg, err := ParseACMEConfig()
	if err != nil || cfg.TXTPropagationTimeout != 5*time.Minute {
		t.Fatalf("default propagation timeout: %v, %v", cfg.TXTPropagationTimeout, err)
	}
	t.Setenv(acmeTXTPropagationTimeout, "12m")
	cfg, err = ParseACMEConfig()
	if err != nil || cfg.TXTPropagationTimeout != 12*time.Minute {
		t.Fatalf("configured propagation timeout: %v, %v", cfg.TXTPropagationTimeout, err)
	}
	for _, value := range []string{"bad", "0", "-1s"} {
		t.Setenv(acmeTXTPropagationTimeout, value)
		if _, err := ParseACMEConfig(); err == nil {
			t.Errorf("accepted invalid timeout %q", value)
		}
	}
}
