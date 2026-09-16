package doctor_test

// The auth check used to probe /api/auth/get-session and switch on the status
// code. That endpoint answers 200 with a null session for unauthenticated
// callers rather than 401, so doctor reported every caller as authenticated -
// including callers with no credential at all, while Wallet and Spend Cap in the
// same run correctly reported them as unauthenticated. These tests pin that the
// auth check now fails when the server refuses the credential.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/keeperhub/cli/cmd/doctor"
	khhttp "github.com/keeperhub/cli/internal/http"
	"github.com/keeperhub/cli/pkg/iostreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authLine returns the doctor output line reporting the Auth check.
func authLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Auth:") {
			return line
		}
	}
	return ""
}

func TestDoctorCmd_AuthFailsWhenCredentialIsRefused(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KH_HOST", "") // ResolveHost reads it ahead of the factory's DefaultHost.
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == khhttp.CredentialProbePath {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer svr.Close()

	ios, outBuf, _, _ := iostreams.Test()
	tc := doctor.NewTestableCmd(newDoctorFactory(ios, svr))
	require.NoError(t, tc.Execute([]string{}))

	line := authLine(outBuf.String())
	assert.Contains(t, line, "not authenticated")
	assert.NotContains(t, line, "pass")
}

func TestDoctorCmd_AuthPassesWhenCredentialIsAccepted(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KH_HOST", "") // ResolveHost reads it ahead of the factory's DefaultHost.
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer svr.Close()

	ios, outBuf, _, _ := iostreams.Test()
	tc := doctor.NewTestableCmd(newDoctorFactory(ios, svr))
	require.NoError(t, tc.Execute([]string{}))

	assert.Contains(t, authLine(outBuf.String()), "authenticated")
}

func TestDoctorCmd_AuthDoesNotProbeTheAnonymousTolerantEndpoint(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KH_HOST", "") // ResolveHost reads it ahead of the factory's DefaultHost.
	// Doctor fans its checks out across goroutines, so the handler runs
	// concurrently and the record of seen paths has to be guarded.
	var mu sync.Mutex
	seen := make(map[string]bool)
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer svr.Close()

	ios, _, _, _ := iostreams.Test()
	tc := doctor.NewTestableCmd(newDoctorFactory(ios, svr))
	require.NoError(t, tc.Execute([]string{}))

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, seen[khhttp.CredentialProbePath], "auth check should probe the credential endpoint")
	// get-session answers 200 to anyone, so probing it can only produce a
	// false green.
	assert.False(t, seen["/api/auth/get-session"], "auth check must not probe get-session")
}
