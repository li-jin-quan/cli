package doctor_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/keeperhub/cli/cmd/doctor"
	"github.com/keeperhub/cli/internal/config"
	khhttp "github.com/keeperhub/cli/internal/http"
	"github.com/keeperhub/cli/pkg/cmdutil"
	"github.com/keeperhub/cli/pkg/iostreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDoctorFactory builds a Factory backed by a test HTTP server.
func newDoctorFactory(ios *iostreams.IOStreams, svr *httptest.Server) *cmdutil.Factory {
	return &cmdutil.Factory{
		AppVersion: "1.2.3",
		IOStreams:  ios,
		Config: func() (config.Config, error) {
			return config.Config{DefaultHost: svr.URL}, nil
		},
		HTTPClient: func() (*khhttp.Client, error) {
			return khhttp.NewClient(khhttp.ClientOptions{
				AppVersion: "1.2.3",
				IOStreams:  ios,
			}), nil
		},
	}
}

// TestDoctorCmd_AllPass verifies that when all endpoints succeed,
// all 6 check names appear in output and the command exits 0.
func TestDoctorCmd_AllPass(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/user":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"usr_1","name":"Dev","email":"dev@example.com","image":null,"isAnonymous":false,"providerId":null,"walletAddress":"0xABCD1234EF567890ABCD1234EF567890ABCD1234"}`))
		case "/api/billing/subscription":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"limits":{"spendCap":100}}`))
		case "/api/chains":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":1,"name":"Ethereum"},{"id":137,"name":"Polygon"}]`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer svr.Close()

	ios, outBuf, _, _ := iostreams.Test()
	f := newDoctorFactory(ios, svr)

	tc := doctor.NewTestableCmd(f)
	err := tc.Execute([]string{})

	require.NoError(t, err)
	out := outBuf.String()
	assert.Contains(t, out, "Auth")
	assert.Contains(t, out, "API")
	assert.Contains(t, out, "Wallet")
	assert.Contains(t, out, "Spend Cap")
	assert.Contains(t, out, "Chains")
	assert.Contains(t, out, "CLI Version")
}

// TestDoctorCmd_OneFail verifies that a failing check causes a non-zero exit.
func TestDoctorCmd_OneFail(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/health":
			// 500 -> API check reports [fail]
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"service unavailable"}`))
		case "/api/user":
			w.WriteHeader(http.StatusUnauthorized)
		case "/api/billing/subscription":
			w.WriteHeader(http.StatusNotFound)
		case "/api/chains":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":1}]`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer svr.Close()

	ios, outBuf, _, _ := iostreams.Test()
	f := newDoctorFactory(ios, svr)

	tc := doctor.NewTestableCmd(f)
	err := tc.Execute([]string{})

	require.Error(t, err, "should return error when any check fails")
	out := outBuf.String()
	assert.Contains(t, out, "[fail]")
}

// TestDoctorCmd_WarnOnly verifies that warnings alone yield exit 0.
func TestDoctorCmd_WarnOnly(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/user":
			// 401 -> wallet warns, not fails
			w.WriteHeader(http.StatusUnauthorized)
		case "/api/billing/subscription":
			// 404 -> billing warns (billing not enabled)
			w.WriteHeader(http.StatusNotFound)
		case "/api/chains":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":1}]`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer svr.Close()

	ios, outBuf, _, _ := iostreams.Test()
	f := newDoctorFactory(ios, svr)

	tc := doctor.NewTestableCmd(f)
	err := tc.Execute([]string{})

	// Warnings only -> exit 0
	require.NoError(t, err)
	out := outBuf.String()
	assert.NotContains(t, out, "[fail]")
	assert.Contains(t, out, "[warn]")
}

// TestDoctorCmd_JSON verifies --json outputs a JSON array with exactly 6 objects.
func TestDoctorCmd_JSON(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/user":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"usr_1","name":"Dev","email":"dev@example.com","image":null,"isAnonymous":false,"providerId":null,"walletAddress":"0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"}`))
		case "/api/billing/subscription":
			w.WriteHeader(http.StatusNotFound)
		case "/api/chains":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":1},{"id":2},{"id":3}]`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer svr.Close()

	ios, outBuf, _, _ := iostreams.Test()
	f := newDoctorFactory(ios, svr)

	tc := doctor.NewTestableCmd(f)
	err := tc.Execute([]string{"--json"})
	require.NoError(t, err)

	var results []map[string]interface{}
	require.NoError(t, json.Unmarshal(outBuf.Bytes(), &results), "output must be valid JSON array")
	assert.Len(t, results, 7, "should have exactly 7 check results")
	for _, r := range results {
		assert.Contains(t, r, "name", "each result must have 'name'")
		assert.Contains(t, r, "status", "each result must have 'status'")
		assert.Contains(t, r, "message", "each result must have 'message'")
	}
}

// TestDoctorCmd_Timeout verifies that a slow endpoint is bounded by 5s timeout.
func TestDoctorCmd_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/user":
			w.WriteHeader(http.StatusUnauthorized)
		case "/api/billing/subscription":
			w.WriteHeader(http.StatusNotFound)
		case "/api/chains":
			// Hang longer than the 5s per-check timeout.
			time.Sleep(7 * time.Second)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer svr.Close()

	ios, outBuf, _, _ := iostreams.Test()
	f := newDoctorFactory(ios, svr)

	start := time.Now()
	tc := doctor.NewTestableCmd(f)
	_ = tc.Execute([]string{})
	elapsed := time.Since(start)

	out := outBuf.String()
	assert.Contains(t, out, "[fail]", "timed-out chain check must report [fail]")
	assert.Less(t, elapsed, 6*time.Second, "must finish before the 7s sleep completes")
}

// TestDoctorCmd_Output verifies all 6 check names appear in non-JSON output.
func TestDoctorCmd_Output(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer svr.Close()

	ios, outBuf, _, _ := iostreams.Test()
	f := newDoctorFactory(ios, svr)

	tc := doctor.NewTestableCmd(f)
	_ = tc.Execute([]string{})

	out := outBuf.String()
	for _, name := range []string{"Auth", "API", "Wallet", "Agentic Wallet", "Spend Cap", "Chains", "CLI Version"} {
		assert.Contains(t, out, name, "output must include check name: %s", name)
	}
}

// TestDoctorCmd_NoLocalJSONFlag verifies the local --json flag was removed.
// The flag must be inherited from root, not defined locally on the command.
func TestDoctorCmd_NoLocalJSONFlag(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &cmdutil.Factory{AppVersion: "1.0.0", IOStreams: ios}
	cmd := doctor.NewDoctorCmd(f)
	localFlag := cmd.Flags().Lookup("json")
	assert.Nil(t, localFlag, "doctor must not define --json locally; use root persistent flag")
}

// TestDoctorCmd_ExitCodeOnFail verifies SilentError is returned on [fail] checks.
func TestDoctorCmd_ExitCodeOnFail(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer svr.Close()

	ios, _, _, _ := iostreams.Test()
	f := newDoctorFactory(ios, svr)

	tc := doctor.NewTestableCmd(f)
	err := tc.Execute([]string{})
	require.Error(t, err)

	var silentErr cmdutil.SilentError
	require.ErrorAs(t, err, &silentErr, "error must be SilentError so root does not double-print")
	assert.Equal(t, 1, cmdutil.ExitCodeForError(err))
}

// walletServer serves the endpoints doctor probes, with GET /api/user
// answering exactly what the API returns for the wallet state under test.
func walletServer(t *testing.T, userBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/user":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(userBody))
		case "/api/health", "/api/auth/session":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/billing/subscription":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"limits":{"spendCap":100}}`))
		case "/api/chains":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":1}]`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
}

// setHome points the home directory at home for the duration of the test.
// os.UserHomeDir reads $HOME on Unix but %USERPROFILE% on Windows, so a
// fixture that sets only HOME leaves the real profile in play on Windows.
//
// It also clears KH_HOST. ResolveHost reads that variable ahead of the
// factory's DefaultHost, so an exported KH_HOST sends these checks to the live
// host instead of the test server and the assertions fail with nothing
// pointing at the cause.
func setHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KH_HOST", "")
}

func runDoctor(t *testing.T, svr *httptest.Server) string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// HOME too: the agentic check resolves ~/.keeperhub/wallet.json through
	// os.UserHomeDir, so without this the suite reads a real credential off the
	// developer's machine and signs a live request with it.
	if os.Getenv("KH_TEST_KEEP_HOME") == "" {
		setHome(t, t.TempDir())
	}
	ios, outBuf, _, _ := iostreams.Test()
	tc := doctor.NewTestableCmd(newDoctorFactory(ios, svr))
	_ = tc.Execute([]string{})
	return outBuf.String()
}

// The check read `address` while the API returns `walletAddress`, so an org
// with a wallet was reported as having none. The body here is the real
// response shape, which is what makes this a regression test rather than a
// restatement of the client's assumption.
func TestDoctorCmd_WalletConnectedIsReported(t *testing.T) {
	svr := walletServer(t, `{"id":"usr_1","name":"Dev","email":"dev@example.com","walletAddress":"0xABCD1234EF567890ABCD1234EF567890ABCD1234"}`)
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.Contains(t, out, "connected")
	assert.NotContains(t, out, "no wallet")
}

func TestDoctorCmd_NullWalletAddressIsActionable(t *testing.T) {
	svr := walletServer(t, `{"id":"usr_1","name":"Dev","email":"dev@example.com","walletAddress":null}`)
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.Contains(t, out, "no wallet configured")
	assert.Contains(t, out, "Settings")
}

// A body carrying only the pre-fix key must not read as connected, so the
// wrong field name cannot quietly come back.
func TestDoctorCmd_LegacyAddressKeyIsNotAccepted(t *testing.T) {
	svr := walletServer(t, `{"address":"0xABCD1234EF567890ABCD1234EF567890ABCD1234"}`)
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.Contains(t, out, "no wallet configured")
}

// agenticWallet writes a wallet config into an isolated HOME and returns its
// secret and subOrgId.
func agenticWallet(t *testing.T) (secret, subOrg, addr string) {
	t.Helper()
	secret, subOrg, addr = "s3cr3t-test-key", "sub_abc123", "0xABCD1234EF567890ABCD1234EF567890ABCD1234"
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("KH_TEST_KEEP_HOME", "1")
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".keeperhub"), 0o700))
	body := `{"subOrgId":"` + subOrg + `","walletAddress":"` + addr + `","hmacSecret":"` + secret + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(home, ".keeperhub", "wallet.json"), []byte(body), 0o600))
	return secret, subOrg, addr
}

// verifyingServer recomputes the signature the way the platform does and
// refuses anything that does not match, so the test fails if the client signs
// the wrong string rather than merely sending some headers.
func verifyingServer(t *testing.T, secret, subOrg string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/agentic-wallet/credit" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}

		gotSubOrg := r.Header.Get("X-KH-Sub-Org")
		ts := r.Header.Get("X-KH-Timestamp")
		gotSig := r.Header.Get("X-KH-Signature")

		bodyDigest := sha256.Sum256(nil)
		signing := "GET\n/api/agentic-wallet/credit\n" + gotSubOrg + "\n" +
			hex.EncodeToString(bodyDigest[:]) + "\n" + ts
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signing))
		want := hex.EncodeToString(mac.Sum(nil))

		if gotSubOrg != subOrg || gotSig != want {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Invalid signature"}`))
			return
		}
		// The timestamp must be recent, as the platform requires.
		parsed, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || time.Since(time.Unix(parsed, 0)) > 5*time.Minute {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Timestamp outside replay window"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"amount":"12.50","currency":"USD","subOrgId":"` + subOrg + `"}`))
	}))
}

func TestDoctorCmd_AgenticWalletSignatureIsAccepted(t *testing.T) {
	secret, subOrg, _ := agenticWallet(t)
	svr := verifyingServer(t, secret, subOrg)
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.Contains(t, out, "Agentic Wallet")
	assert.Contains(t, out, "12.50 USD credit")
}

func TestDoctorCmd_AgenticWalletRejectedSignature(t *testing.T) {
	_, subOrg, _ := agenticWallet(t)
	// Server holds a different secret, so a correct client still fails to verify.
	svr := verifyingServer(t, "a-different-secret", subOrg)
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.Contains(t, out, "rejected by the platform")
}

func TestDoctorCmd_AgenticWalletNotConfigured(t *testing.T) {
	setHome(t, t.TempDir())
	svr := walletServer(t, `{"walletAddress":"0xABC"}`)
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.Contains(t, out, "not configured (kh wallet add)")
}

// The secret is the wallet's only credential and must not reach stdout, which
// is the surface an agent will capture and log.
func TestDoctorCmd_AgenticWalletNeverPrintsTheSecret(t *testing.T) {
	secret, subOrg, _ := agenticWallet(t)
	svr := verifyingServer(t, secret, subOrg)
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.NotContains(t, out, secret)
}

// The platform builds `amount` with toFixed(2), so it is a JSON string. A
// float64 field decodes it as an error and the check silently degrades to
// "could not parse", which is how this shipped broken the first time.
func TestDoctorCmd_AgenticCreditAmountIsAString(t *testing.T) {
	secret, subOrg, _ := agenticWallet(t)
	svr := verifyingServer(t, secret, subOrg)
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.NotContains(t, out, "could not parse credit response")
	assert.Contains(t, out, "12.50 USD credit")
}

// A 200 that is not the credit endpoint must not render as a funded wallet
// with zero balance.
func TestDoctorCmd_AgenticUnexpectedBodyIsNotAPass(t *testing.T) {
	secret, subOrg, _ := agenticWallet(t)
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer svr.Close()
	_ = secret
	_ = subOrg

	out := runDoctor(t, svr)

	assert.Contains(t, out, "unexpected credit response shape")
	assert.NotContains(t, out, "0.00")
}

func TestDoctorCmd_AgenticUnknownSubOrgIsActionable(t *testing.T) {
	agenticWallet(t)
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/agentic-wallet/credit" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"Unknown sub-org","code":"WALLET_NOT_FOUND"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.Contains(t, out, "unknown to this host")
}

// Absent is the normal state on most installs, so it must not warn.
func TestDoctorCmd_AgenticNotConfiguredIsNotAWarning(t *testing.T) {
	setHome(t, t.TempDir())
	svr := walletServer(t, `{"walletAddress":"0xABC"}`)
	defer svr.Close()

	out := runDoctor(t, svr)

	assert.Contains(t, out, "[pass] Agentic Wallet: not configured")
}
