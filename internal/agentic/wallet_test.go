package agentic_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keeperhub/cli/internal/agentic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Produced by the platform's own computeSignature (lib/agentic-wallet/hmac.ts)
// for these inputs. Pinning the Node output rather than a value this package
// generated is the point: a signature that only agrees with itself would still
// be rejected by the server.
const (
	fixtureSecret    = "s3cr3t-test-key"
	fixtureSubOrg    = "sub_abc123"
	fixturePath      = "/api/agentic-wallet/credit"
	fixtureTimestamp = 1786000000
	fixtureSignature = "3becc7ba14cd84066fc6194588db62471841ccfc012d4ae9e8332f1fed68c592"
)

func TestSign_MatchesPlatformImplementation(t *testing.T) {
	got := agentic.Sign(
		fixtureSecret, "GET", fixturePath, fixtureSubOrg, "", fixtureTimestamp,
	)
	assert.Equal(t, fixtureSignature, got)
}

func TestSign_EveryFieldIsBound(t *testing.T) {
	base := agentic.Sign(fixtureSecret, "GET", fixturePath, fixtureSubOrg, "", fixtureTimestamp)

	cases := map[string]string{
		"method":    agentic.Sign(fixtureSecret, "POST", fixturePath, fixtureSubOrg, "", fixtureTimestamp),
		"path":      agentic.Sign(fixtureSecret, "GET", "/api/agentic-wallet/sign", fixtureSubOrg, "", fixtureTimestamp),
		"subOrgId":  agentic.Sign(fixtureSecret, "GET", fixturePath, "sub_other", "", fixtureTimestamp),
		"body":      agentic.Sign(fixtureSecret, "GET", fixturePath, fixtureSubOrg, "{}", fixtureTimestamp),
		"timestamp": agentic.Sign(fixtureSecret, "GET", fixturePath, fixtureSubOrg, "", fixtureTimestamp+1),
		"secret":    agentic.Sign("other-secret", "GET", fixturePath, fixtureSubOrg, "", fixtureTimestamp),
	}

	for field, sig := range cases {
		assert.NotEqual(t, base, sig, "%s must be bound into the signature", field)
	}
}

// setHome points the home directory at home for the duration of the test.
// os.UserHomeDir reads $HOME on Unix but %USERPROFILE% on Windows, so a
// fixture that sets only HOME leaves the real profile in play on Windows.
func setHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func writeWallet(t *testing.T, body string) {
	t.Helper()
	home := t.TempDir()
	setHome(t, home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".keeperhub"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(home, ".keeperhub", agentic.ConfigName), []byte(body), 0o600,
	))
}

func TestLoad_ReadsTheWallet(t *testing.T) {
	writeWallet(t, `{"subOrgId":"sub_abc123","walletAddress":"0xabc","hmacSecret":"s3cr3t"}`)

	cfg, err := agentic.Load()

	require.NoError(t, err)
	assert.Equal(t, "sub_abc123", cfg.SubOrgID)
	assert.Equal(t, "0xabc", cfg.WalletAddress)
}

func TestLoad_MissingFileIsNotConfigured(t *testing.T) {
	setHome(t, t.TempDir())

	_, err := agentic.Load()

	assert.ErrorIs(t, err, agentic.ErrNotConfigured)
}

func TestLoad_MalformedConfigReportsAnError(t *testing.T) {
	writeWallet(t, `not json`)

	_, err := agentic.Load()

	require.Error(t, err)
	assert.NotErrorIs(t, err, agentic.ErrNotConfigured)
}

// The secret is the wallet's only credential, so it must never appear in a
// rendered error, which is the one string a caller is likely to print.
func TestLoad_ErrorNeverCarriesTheSecret(t *testing.T) {
	writeWallet(t, `{"subOrgId":"sub_abc123","hmacSecret":"s3cr3t-test-key","walletAddress":`)

	_, err := agentic.Load()

	require.Error(t, err)
	assert.NotContains(t, err.Error(), fixtureSecret)
}

func TestConfig_StringRedactsTheSecret(t *testing.T) {
	cfg := agentic.Config{
		SubOrgID:      "sub_abc123",
		WalletAddress: "0xabc",
		HMACSecret:    fixtureSecret,
	}

	rendered := fmt.Sprintf("%v", cfg)

	assert.NotContains(t, rendered, fixtureSecret)
	assert.Contains(t, rendered, "redacted")
	assert.Contains(t, rendered, "sub_abc123")
}

// An unset secret must not read as "redacted", which would hide the fact that
// the config never carried one.
func TestConfig_StringDistinguishesAnUnsetSecret(t *testing.T) {
	rendered := fmt.Sprintf("%v", agentic.Config{SubOrgID: "sub_abc123"})

	assert.Contains(t, rendered, "unset")
}

func TestLoad_IncompleteConfigIsDistinctFromAbsent(t *testing.T) {
	writeWallet(t, `{"subOrgId":"sub_abc123","walletAddress":"0xabc"}`)

	_, err := agentic.Load()

	assert.ErrorIs(t, err, agentic.ErrIncompleteConfig)
	assert.NotErrorIs(t, err, agentic.ErrNotConfigured)
}

// The signed path comes from the request, so a host carrying a path prefix
// signs what it actually sends rather than a hard-coded constant.
func TestSignRequest_SignsThePathItSends(t *testing.T) {
	cfg := agentic.Config{SubOrgID: fixtureSubOrg, HMACSecret: fixtureSecret}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/kh"+fixturePath, nil)
	require.NoError(t, err)

	agentic.SignRequest(req, cfg, "", time.Unix(fixtureTimestamp, 0))

	want := agentic.Sign(
		fixtureSecret, http.MethodGet, "/kh"+fixturePath, fixtureSubOrg, "", fixtureTimestamp,
	)
	assert.Equal(t, want, req.Header.Get(agentic.HeaderSignature))
	assert.NotEqual(t, fixtureSignature, req.Header.Get(agentic.HeaderSignature))
	assert.Equal(t, fixtureSubOrg, req.Header.Get(agentic.HeaderSubOrg))
}

func TestSignRequest_MatchesTheUnprefixedFixture(t *testing.T) {
	cfg := agentic.Config{SubOrgID: fixtureSubOrg, HMACSecret: fixtureSecret}
	req, err := http.NewRequest(http.MethodGet, "https://example.com"+fixturePath, nil)
	require.NoError(t, err)

	agentic.SignRequest(req, cfg, "", time.Unix(fixtureTimestamp, 0))

	assert.Equal(t, fixtureSignature, req.Header.Get(agentic.HeaderSignature))
}

// The secret must never reach the headers in any form other than the digest.
func TestSignRequest_NeverSendsTheSecret(t *testing.T) {
	cfg := agentic.Config{SubOrgID: fixtureSubOrg, HMACSecret: fixtureSecret}
	req, err := http.NewRequest(http.MethodGet, "https://example.com"+fixturePath, nil)
	require.NoError(t, err)

	agentic.SignRequest(req, cfg, "", time.Unix(fixtureTimestamp, 0))

	for _, values := range req.Header {
		for _, v := range values {
			assert.NotContains(t, v, fixtureSecret)
		}
	}
}
