package certbot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

type accountKeyCache struct {
	data []byte
	err  error
}

func (c *accountKeyCache) Get(context.Context, string) ([]byte, error) {
	return c.data, c.err
}

func (c *accountKeyCache) Put(_ context.Context, _ string, data []byte) error {
	c.data, c.err = data, nil
	return nil
}

func (c *accountKeyCache) Delete(context.Context, string) error { return nil }

func TestLoadAccountKeyOnCacheMiss(t *testing.T) {
	cache := &accountKeyCache{err: autocert.ErrCacheMiss}
	key, err := loadAccountKey(context.Background(), cache)
	if err != nil {
		t.Fatalf("loadAccountKey: %v", err)
	}
	if key.N.BitLen() < 2048 {
		t.Fatalf("account key is too small: %d bits", key.N.BitLen())
	}
	stored, err := x509.ParsePKCS1PrivateKey(cache.data)
	if err != nil || stored.N.Cmp(key.N) != 0 {
		t.Fatalf("stored key differs from returned key: %v", err)
	}
}

func TestLoadAccountKeyCacheError(t *testing.T) {
	cacheErr := errors.New("cache unavailable")
	_, err := loadAccountKey(context.Background(), &accountKeyCache{err: cacheErr})
	if !errors.Is(err, cacheErr) {
		t.Fatalf("expected cache error, got %v", err)
	}
}

func TestLoadAccountKeyCached(t *testing.T) {
	original, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cache := &accountKeyCache{data: x509.MarshalPKCS1PrivateKey(original)}
	key, err := loadAccountKey(context.Background(), cache)
	if err != nil || key.N.Cmp(original.N) != 0 {
		t.Fatalf("expected cached key, got %v", err)
	}
}
