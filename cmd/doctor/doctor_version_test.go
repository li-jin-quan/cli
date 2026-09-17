package doctor_test

// checkCLIVersion used to only print the local version string, unconditionally
// pass, and never compare against anything -- the server had no way to tell an
// out-of-date CLI that it was behind. These tests pin the comparison against
// the KH-Minimum-CLI-Version header the server advertises on /api/*
// (khhttp.MinimumVersionHeader).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keeperhub/cli/cmd/doctor"
	"github.com/keeperhub/cli/internal/config"
	khhttp "github.com/keeperhub/cli/internal/http"
	"github.com/keeperhub/cli/pkg/cmdutil"
	"github.com/keeperhub/cli/pkg/iostreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cliVersionLine returns the doctor output line reporting the CLI Version check.
func cliVersionLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "CLI Version:") {
			return line
		}
	}
	return ""
}

// versionDoctorFactory builds a Factory pinned to appVersion, backed by a test
// server that advertises minimumHeader (empty means the header is omitted).
func versionDoctorFactory(ios *iostreams.IOStreams, appVersion, minimumHeader string) *cmdutil.Factory {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if minimumHeader != "" && strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set(khhttp.MinimumVersionHeader, minimumHeader)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	return &cmdutil.Factory{
		AppVersion: appVersion,
		IOStreams:  ios,
		Config: func() (config.Config, error) {
			return config.Config{DefaultHost: svr.URL}, nil
		},
		HTTPClient: func() (*khhttp.Client, error) {
			return khhttp.NewClient(khhttp.ClientOptions{
				AppVersion: appVersion,
				IOStreams:  ios,
			}), nil
		},
	}
}

func TestDoctorCmd_CLIVersionPassesWhenServerAdvertisesNoMinimum(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())
	t.Setenv("KH_HOST", "") // ResolveHost reads it ahead of the factory's DefaultHost.
	ios, outBuf, _, _ := iostreams.Test()
	tc := doctor.NewTestableCmd(versionDoctorFactory(ios, "1.2.3", ""))
	require.NoError(t, tc.Execute([]string{}))

	line := cliVersionLine(outBuf.String())
	assert.Contains(t, line, "pass")
	assert.Contains(t, line, "v1.2.3")
}

func TestDoctorCmd_CLIVersionWarnsWhenBelowServerMinimum(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())
	t.Setenv("KH_HOST", "") // ResolveHost reads it ahead of the factory's DefaultHost.
	ios, outBuf, _, _ := iostreams.Test()
	tc := doctor.NewTestableCmd(versionDoctorFactory(ios, "0.3.0", "0.11.1"))
	require.NoError(t, tc.Execute([]string{}))

	line := cliVersionLine(outBuf.String())
	assert.Contains(t, line, "warn")
	assert.Contains(t, line, "outdated")
	assert.Contains(t, line, "0.11.1")
	assert.Contains(t, line, "Run: kh update")
}

func TestDoctorCmd_CLIVersionPassesWhenAtServerMinimum(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())
	t.Setenv("KH_HOST", "") // ResolveHost reads it ahead of the factory's DefaultHost.
	ios, outBuf, _, _ := iostreams.Test()
	tc := doctor.NewTestableCmd(versionDoctorFactory(ios, "0.11.1", "0.11.1"))
	require.NoError(t, tc.Execute([]string{}))

	line := cliVersionLine(outBuf.String())
	assert.Contains(t, line, "pass")
	assert.NotContains(t, line, "outdated")
}

func TestDoctorCmd_CLIVersionReportsDevBuildWithoutComparing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	setHome(t, t.TempDir())
	t.Setenv("KH_HOST", "") // ResolveHost reads it ahead of the factory's DefaultHost.
	ios, outBuf, _, _ := iostreams.Test()
	// A minimum far above any real release: if dev builds were compared,
	// this would incorrectly warn.
	tc := doctor.NewTestableCmd(versionDoctorFactory(ios, "dev", "99.0.0"))
	require.NoError(t, tc.Execute([]string{}))

	line := cliVersionLine(outBuf.String())
	assert.Contains(t, line, "development build")
	assert.NotContains(t, line, "outdated")
}
