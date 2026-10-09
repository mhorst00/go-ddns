package certbot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/acme"
)

func TestEnsureAccount(t *testing.T) {
	for _, tc := range []struct {
		name          string
		lookupExists  bool
		raced         bool
		wantRegisters int32
	}{
		{"existing", true, false, 0},
		{"new", false, false, 1},
		{"registered concurrently", false, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lookups, registrations atomic.Int32
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/directory":
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Replay-Nonce", "nonce")
					json.NewEncoder(w).Encode(map[string]string{"newAccount": server.URL + "/account", "newOrder": server.URL + "/order"})
				case "/account":
					var jws struct {
						Payload string `json:"payload"`
					}
					if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
						t.Errorf("decode signed account request: %v", err)
					}
					payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
					if err != nil {
						t.Errorf("decode payload: %v", err)
					}
					var request struct {
						OnlyReturnExisting bool `json:"onlyReturnExisting"`
					}
					if err := json.Unmarshal(payload, &request); err != nil {
						t.Errorf("decode account request: %v", err)
					}
					w.Header().Set("Replay-Nonce", "nonce")
					w.Header().Set("Content-Type", "application/json")
					if strings.Contains(string(payload), "onlyReturnExisting") {
						lookups.Add(1)
						if !tc.lookupExists && lookups.Load() == 1 {
							w.WriteHeader(http.StatusBadRequest)
							w.Write([]byte(`{"type":"urn:ietf:params:acme:error:accountDoesNotExist"}`))
							return
						}
					} else {
						registrations.Add(1)
					}
					w.Header().Set("Location", server.URL+"/existing-account")
					if request.OnlyReturnExisting || tc.lookupExists || tc.raced {
						w.WriteHeader(http.StatusOK)
					} else {
						w.WriteHeader(http.StatusCreated)
					}
					w.Write([]byte(`{"status":"valid"}`))
				default:
					t.Errorf("unexpected ACME request: %s", r.URL)
				}
			}))
			defer server.Close()

			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			client := &acme.Client{DirectoryURL: server.URL + "/directory", Key: key}
			account, err := ensureAccount(context.Background(), client, []string{"mailto:admin@example.org"})
			if err != nil {
				t.Fatalf("ensureAccount: %v", err)
			}
			if account.URI != server.URL+"/existing-account" || registrations.Load() != tc.wantRegisters {
				t.Fatalf("account URI=%q, registrations=%d; want  %d", account.URI, registrations.Load(), tc.wantRegisters)
			}
		})
	}
}
