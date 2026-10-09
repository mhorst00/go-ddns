package certbot

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	// ref: https://eff-certbot.readthedocs.io/en/stable/using.html#pre-and-post-validation-hooks
	certBotIdentifier          = "CERTBOT_IDENTIFIER"           // The domain or IP address being authenticated
	certBotValidation          = "CERTBOT_VALIDATION"           // The validation string
	certBotToken               = "CERTBOT_TOKEN"                // Resource name part of the HTTP-01 challenge (HTTP-01 only)
	certBotRemainingChallenges = "CERTBOT_REMAINING_CHALLENGES" // Number of challenges remaining after the current challenge
	certBotAllIdentifiers      = "CERTBOT_ALL_IDENTIFIERS"      // A comma-separated list of all identifiers challenged for the current certificate

	// ACME configuration variables
	acmeMailAddresses         = "ACME_MAIL_ADDRESSES"          // A comms-separated list of all mail addresses used on the account
	acmeChallengeTimeout      = "ACME_CHALLENGE_TIMEOUT"       // Parsed by the time library :default: 1m
	acmeTXTPropagationTimeout = "ACME_TXT_PROPAGATION_TIMEOUT" // DNS TXT polling deadline, independent of ACME_CHALLENGE_TIMEOUT; default: 5m
	acmeRenewBefore           = "ACME_RENEW_BEFORE"
	acmeCacheDir              = "ACME_CACHE_DIR"

	// ACME configuration defaults
	ACMETXTPrefix         = "_acme-challenge"
	defaultAccountKeyName = "account.key"
	defaultACMECacheDir   = "go-ddns"

	ACMEStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type CertBotParameters struct {
	Identifier          string
	Validation          string
	Token               string
	RemainingChallenges int64
	AllIdentifiers      []string
}
type ACMEConfig struct {
	CacheDir              string
	MailAddresses         []string
	ACMEURL               string
	Timeout               time.Duration
	TXTPropagationTimeout time.Duration
	RenewBefore           time.Duration
}

func ParseACMEConfig() (config ACMEConfig, err error) {
	cacheDir := os.Getenv(acmeCacheDir)
	if cacheDir == "" {
		// default to userCacheDir
		cacheDir, err = os.UserCacheDir()
		if err != nil {
			return config, fmt.Errorf("getting default usercachedir: %w", err)
		}
		cacheDir = path.Join(cacheDir, defaultACMECacheDir)
	}
	config.CacheDir = path.Join(cacheDir)

	mailAddresses := strings.Split(os.Getenv(acmeMailAddresses), ",")
	if len(mailAddresses) == 0 {
		return config, fmt.Errorf("%s is required", acmeMailAddresses)
	}
	config.ACMEURL = autocert.DefaultACMEDirectory
	// staging environment
	//config.ACMEURL = ACMEStagingURL

	// Timeout
	config.Timeout = 1 * time.Minute
	// Check if we have user configured timeout
	timeoutString := os.Getenv(acmeChallengeTimeout)
	if timeoutString != "" {
		config.Timeout, err = time.ParseDuration(timeoutString)
		if err != nil {
			return config, fmt.Errorf("%s=%s is invalid: %w", acmeChallengeTimeout, timeoutString, err)
		}
	}
	config.TXTPropagationTimeout = 5 * time.Minute
	if value := os.Getenv(acmeTXTPropagationTimeout); value != "" {
		config.TXTPropagationTimeout, err = time.ParseDuration(value)
		if err != nil || config.TXTPropagationTimeout <= 0 {
			return config, fmt.Errorf("%s=%q must be a positive duration", acmeTXTPropagationTimeout, value)
		}
	}
	config.RenewBefore = 30 * 24 * time.Hour
	renewDurationString := os.Getenv(acmeRenewBefore)
	if renewDurationString != "" {
		config.RenewBefore, err = time.ParseDuration(renewDurationString)
		if err != nil {
			return config, fmt.Errorf("%s=%s is invalid: %w", acmeRenewBefore, renewDurationString, err)
		}
	}
	return config, err
}

func ParseParams() (params CertBotParameters, err error) {
	params.Identifier = os.Getenv(certBotIdentifier)
	if params.Identifier == "" {
		return params, fmt.Errorf("%s is required", certBotIdentifier)
	}
	params.Validation = os.Getenv(certBotValidation)
	if params.Validation == "" {
		return params, fmt.Errorf("%s is required", certBotValidation)
	}
	params.Token = os.Getenv(certBotToken)
	remainChallenges := os.Getenv(certBotRemainingChallenges)
	if remainChallenges != "" {
		params.RemainingChallenges, err = strconv.ParseInt(remainChallenges, 10, 0)
		if err != nil {
			return params, fmt.Errorf("%s not a number: %w", certBotRemainingChallenges, err)
		}
	}
	allIdentifiers := os.Getenv(certBotRemainingChallenges)
	if allIdentifiers != "" {
		params.AllIdentifiers = strings.Split(allIdentifiers, ",")
	}
	return params, err
}
