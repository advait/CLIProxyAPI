package usagerouting

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const claudeUsageBody = `{"five_hour": null, "seven_day": {"utilization": 72.0, "resets_at": "2026-11-12T23:00:00.729749+00:00"},
"seven_day_opus": null, "extra_usage": {"is_enabled": true, "monthly_limit": 4000, "used_credits": 584.0}}`

const codexUsageBody = `{"email":"x@example.com","plan_type":"pro","rate_limit":{"allowed":true,"limit_reached":false,
"primary_window":{"used_percent":12,"limit_window_seconds":604800,"reset_after_seconds":140700,"reset_at":1794600000},
"secondary_window":null}}`

const codexCreditsBody = `{"available_count":2,"credits":[{"status":"available","expires_at":"2026-11-30T08:00:00Z"},
{"status":"redeemed","expires_at":"2026-11-20T08:00:00Z"},{"status":"available","expires_at":"2026-12-02T08:00:00Z"}]}`

func TestParseClaudeUsage(t *testing.T) {
	var snapshot coreauth.UsageSnapshot
	parseClaudeUsage([]byte(claudeUsageBody), &snapshot)
	if snapshot.Primary != nil {
		t.Fatalf("five_hour null must leave Primary nil, got %+v", snapshot.Primary)
	}
	if snapshot.Secondary == nil || snapshot.Secondary.UsedPercent != 72 ||
		!snapshot.Secondary.ResetAt.Equal(time.Date(2026, 11, 12, 23, 0, 0, 729749000, time.UTC)) {
		t.Fatalf("Secondary = %+v", snapshot.Secondary)
	}
	if !snapshot.ExtraUsageEnabled {
		t.Fatal("extra usage flag not parsed")
	}
}

func TestParseCodexUsageAndCredits(t *testing.T) {
	var snapshot coreauth.UsageSnapshot
	parseCodexUsage([]byte(codexUsageBody), &snapshot)
	if snapshot.LimitReached || snapshot.Primary == nil || snapshot.Primary.UsedPercent != 12 ||
		!snapshot.Primary.ResetAt.Equal(time.Unix(1794600000, 0)) || snapshot.Secondary != nil {
		t.Fatalf("snapshot = %+v primary=%+v", snapshot, snapshot.Primary)
	}
	var blocked coreauth.UsageSnapshot
	parseCodexUsage([]byte(`{"rate_limit":{"allowed":false,"limit_reached":false}}`), &blocked)
	if !blocked.LimitReached {
		t.Fatal("allowed=false must count as limit reached")
	}
	expiries := parseCodexResetCredits([]byte(codexCreditsBody))
	if len(expiries) != 2 {
		t.Fatalf("expiries = %v, want the two available credits", expiries)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPollOnceFetchesStoresAndCaches(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{AuthDir: filepath.Join(dir, "auths")}
	cfg.Routing.Strategy = Strategy
	manager := coreauth.NewManager(nil, nil, nil)
	ctx := context.Background()
	for _, auth := range []*coreauth.Auth{
		{ID: "claude-1", Provider: "claude", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "tok-c", "email": "c@example.com"}},
		{ID: "codex-1", Provider: "codex", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "tok-x", "account_id": "acct"}},
		{ID: "claude-key", Provider: "claude", Status: coreauth.StatusActive},
	} {
		if _, errRegister := manager.Register(coreauth.WithSkipPersist(ctx), auth); errRegister != nil {
			t.Fatalf("Register: %v", errRegister)
		}
	}
	var requests []string
	poller := NewPoller(manager, func() *config.Config { return cfg })
	poller.client = func(context.Context, *config.Config, *coreauth.Auth) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			requests = append(requests, r.URL.String()+" "+r.Header.Get("Authorization")+" "+r.Header.Get("ChatGPT-Account-Id"))
			body := map[string]string{claudeUsageURL: claudeUsageBody, codexUsageURL: codexUsageBody, codexResetCreditsURL: codexCreditsBody}[r.URL.String()]
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
	}
	settings := SettingsFromConfig(cfg)
	if !settings.Enabled || settings.PollInterval != defaultPollInterval || settings.CacheFile != filepath.Join(dir, "usage-cache.json") {
		t.Fatalf("settings = %+v", settings)
	}
	poller.PollOnce(ctx, settings)
	t.Cleanup(func() {
		coreauth.ForgetUsageSnapshot("claude-1")
		coreauth.ForgetUsageSnapshot("codex-1")
	})

	if len(requests) != 3 {
		t.Fatalf("requests = %v, want claude usage + codex usage + credits (API-key auth skipped)", requests)
	}
	for _, want := range []string{claudeUsageURL + " Bearer tok-c ", codexUsageURL + " Bearer tok-x acct"} {
		found := false
		for _, got := range requests {
			found = found || got == want
		}
		if !found {
			t.Fatalf("missing request %q in %v", want, requests)
		}
	}
	snapshots := coreauth.UsageSnapshots()
	if len(snapshots) != 2 || snapshots[0].AuthID != "claude-1" || snapshots[0].Email != "c@example.com" || len(snapshots[1].ResetCreditExpiries) != 2 {
		t.Fatalf("snapshots = %+v", snapshots)
	}
	info, errStat := os.Stat(settings.CacheFile)
	if errStat != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file: %v mode=%v", errStat, info)
	}
}

func TestSettingsFromConfigClampsAndWeights(t *testing.T) {
	weight := 5.0
	cfg := &config.Config{}
	cfg.Routing.Strategy = "round-robin"
	cfg.Routing.UsageAware.PollInterval = "10s"
	cfg.Routing.UsageAware.SecondaryWeight = &weight
	settings := SettingsFromConfig(cfg)
	if settings.Enabled || settings.PollInterval != minPollInterval || settings.Weights.Secondary != 5 || settings.Weights.Primary != 1000 {
		t.Fatalf("settings = %+v", settings)
	}
}
