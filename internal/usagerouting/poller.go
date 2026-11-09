// Package usagerouting polls subscription usage for Claude and Codex OAuth
// credentials and feeds the usage-aware routing strategy (fork addition).
package usagerouting

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	// Strategy is the routing.strategy value that enables usage-aware routing.
	Strategy = "usage-aware"

	defaultPollInterval = 5 * time.Minute
	minPollInterval     = time.Minute
	// probeTimeout bounds one usage request. The probe is a standalone metadata
	// call, not model traffic, so a hung request must not stall the poll loop.
	probeTimeout = 20 * time.Second

	claudeUsageURL       = "https://api.anthropic.com/api/oauth/usage"
	claudeOAuthBeta      = "oauth-2025-04-20"
	claudeUsageUserAgent = "claude-cli/2.1.280 (external, cli)"
	codexUsageURL        = "https://chatgpt.com/backend-api/wham/usage"
	codexResetCreditsURL = "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits"
	codexUsageUserAgent  = "codex-tui/0.154.0 (Mac OS 26.5.2; arm64) iTerm.app/3.6.11 (codex-tui; 0.154.0)"
)

// Settings is the normalized usage-aware configuration.
type Settings struct {
	Enabled      bool
	PollInterval time.Duration
	CacheFile    string
	Weights      coreauth.UsageWeights
}

// SettingsFromConfig normalizes routing.usage-aware.
func SettingsFromConfig(cfg *config.Config) Settings {
	settings := Settings{PollInterval: defaultPollInterval, Weights: coreauth.DefaultUsageWeights()}
	if cfg == nil {
		return settings
	}
	settings.Enabled = strings.EqualFold(strings.TrimSpace(cfg.Routing.Strategy), Strategy)
	ua := cfg.Routing.UsageAware
	if raw := strings.TrimSpace(ua.PollInterval); raw != "" {
		if parsed, errParse := time.ParseDuration(raw); errParse == nil {
			settings.PollInterval = max(parsed, minPollInterval)
		} else {
			log.Warnf("usage routing: invalid poll-interval %q, using %s", raw, defaultPollInterval)
		}
	}
	if ua.PrimaryWeight != nil {
		settings.Weights.Primary = *ua.PrimaryWeight
	}
	if ua.SecondaryWeight != nil {
		settings.Weights.Secondary = *ua.SecondaryWeight
	}
	if ua.ResetCreditWeight != nil {
		settings.Weights.ResetCredit = *ua.ResetCreditWeight
	}
	settings.CacheFile = strings.TrimSpace(ua.CacheFile)
	if settings.CacheFile == "" {
		if dir, errDir := util.ResolveAuthDir(cfg.AuthDir); errDir == nil && dir != "" {
			settings.CacheFile = filepath.Join(filepath.Dir(filepath.Clean(dir)), "usage-cache.json")
		}
	}
	return settings
}

// Poller periodically refreshes usage snapshots.
type Poller struct {
	manager *coreauth.Manager
	config  func() *config.Config
	client  func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) *http.Client
	now     func() time.Time

	loadOnce sync.Once
	pollMu   sync.Mutex
	wake     chan struct{}
}

var (
	activeMu sync.RWMutex
	active   *Poller
)

// Refresh polls every credential immediately using the running poller.
func Refresh(ctx context.Context) error {
	activeMu.RLock()
	p := active
	activeMu.RUnlock()
	if p == nil {
		return fmt.Errorf("usage poller is not running")
	}
	settings := SettingsFromConfig(p.config())
	if !settings.Enabled {
		return fmt.Errorf("routing.strategy is not %q", Strategy)
	}
	p.loadOnce.Do(func() { p.loadState(settings.CacheFile) })
	p.PollOnce(ctx, settings)
	return nil
}

// NewPoller creates a poller reading credentials from manager and settings from cfgFn.
func NewPoller(manager *coreauth.Manager, cfgFn func() *config.Config) *Poller {
	return &Poller{
		manager: manager,
		config:  cfgFn,
		client: func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) *http.Client {
			return helps.NewUtlsHTTPClient(ctx, cfg, auth, probeTimeout)
		},
		now:  time.Now,
		wake: make(chan struct{}, 1),
	}
}

// Wake triggers an immediate poll (for example after a config change).
func (p *Poller) Wake() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Run polls until ctx is cancelled. Settings are re-read every cycle so config
// hot reloads take effect without a restart.
func (p *Poller) Run(ctx context.Context) {
	activeMu.Lock()
	active = p
	activeMu.Unlock()
	for {
		settings := SettingsFromConfig(p.config())
		coreauth.ConfigureUsageRouting(settings.Enabled, settings.Weights, settings.PollInterval)
		if settings.Enabled {
			p.loadOnce.Do(func() { p.loadState(settings.CacheFile) })
			p.PollOnce(ctx, settings)
		}
		timer := time.NewTimer(settings.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-p.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// PollOnce refreshes every eligible credential and persists the cache.
func (p *Poller) PollOnce(ctx context.Context, settings Settings) {
	p.pollMu.Lock()
	defer p.pollMu.Unlock()
	cfg := p.config()
	seen := make(map[string]struct{})
	var samples []coreauth.UsageSample
	for _, auth := range p.manager.List() {
		provider, ok := eligibleProvider(auth)
		if !ok {
			continue
		}
		seen[auth.ID] = struct{}{}
		snapshot, errFetch := p.fetch(ctx, cfg, auth, provider)
		if errFetch != nil {
			// Keep the previous snapshot; it ages out via staleness.
			log.Warnf("usage routing: fetch %s usage for %s failed: %v", provider, auth.ID, errFetch)
			continue
		}
		coreauth.StoreUsageSnapshot(snapshot)
		samples = append(samples, coreauth.SampleFromSnapshot(snapshot))
		log.Debugf("usage routing: %s primary=%s secondary=%s", auth.ID, describeWindow(snapshot.Primary), describeWindow(snapshot.Secondary))
	}
	for _, snapshot := range coreauth.UsageSnapshots() {
		if _, ok := seen[snapshot.AuthID]; !ok {
			coreauth.ForgetUsageSnapshot(snapshot.AuthID)
		}
	}
	p.saveCache(settings.CacheFile)
	coreauth.AppendUsageHistory(samples...)
	appendHistoryFile(historyFile(settings.CacheFile), samples)
}

// historyFile is the JSONL usage history kept next to the cache file.
func historyFile(cacheFile string) string {
	if cacheFile == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(cacheFile), "usage-history.jsonl")
}

func appendHistoryFile(path string, samples []coreauth.UsageSample) {
	if path == "" || len(samples) == 0 {
		return
	}
	fh, errOpen := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if errOpen != nil {
		log.Warnf("usage routing: open history %s: %v", path, errOpen)
		return
	}
	defer func() {
		if errClose := fh.Close(); errClose != nil {
			log.Warnf("usage routing: close history %s: %v", path, errClose)
		}
	}()
	encoder := json.NewEncoder(fh)
	for _, sample := range samples {
		if errEncode := encoder.Encode(sample); errEncode != nil {
			log.Warnf("usage routing: write history %s: %v", path, errEncode)
			return
		}
	}
}

// loadHistory reads retained samples and rewrites the file without expired ones.
func (p *Poller) loadHistory(path string) {
	if path == "" {
		return
	}
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		if !os.IsNotExist(errRead) {
			log.Warnf("usage routing: read history %s: %v", path, errRead)
		}
		return
	}
	cutoff := p.now().Add(-coreauth.UsageHistoryRetention)
	var kept []coreauth.UsageSample
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var sample coreauth.UsageSample
		if errDecode := json.Unmarshal([]byte(line), &sample); errDecode != nil || sample.At.Before(cutoff) {
			continue
		}
		kept = append(kept, sample)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].At.Before(kept[j].At) })
	coreauth.AppendUsageHistory(kept...)
	tmp := path + ".tmp"
	if errWrite := os.WriteFile(tmp, nil, 0o600); errWrite == nil {
		appendHistoryFile(tmp, kept)
		if errRename := os.Rename(tmp, path); errRename != nil {
			log.Warnf("usage routing: compact history %s: %v", path, errRename)
		}
	}
	log.Infof("usage routing: loaded %d usage history samples", len(kept))
}

func eligibleProvider(auth *coreauth.Auth) (string, bool) {
	if auth == nil || auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return "", false
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if provider != "claude" && provider != "codex" {
		return "", false
	}
	if accessToken(auth) == "" {
		return "", false // API-key credentials have no subscription usage.
	}
	return provider, true
}

func accessToken(auth *coreauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	token, _ := auth.Metadata["access_token"].(string)
	return strings.TrimSpace(token)
}

func metadataString(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[key].(string)
	return strings.TrimSpace(value)
}

func (p *Poller) fetch(ctx context.Context, cfg *config.Config, auth *coreauth.Auth, provider string) (coreauth.UsageSnapshot, error) {
	snapshot := coreauth.UsageSnapshot{AuthID: auth.ID, Provider: provider, Email: metadataString(auth, "email"), Plan: metadataString(auth, "plan_type")}
	headers := http.Header{"Authorization": {"Bearer " + accessToken(auth)}, "Accept": {"application/json"}}
	switch provider {
	case "claude":
		headers.Set("anthropic-beta", claudeOAuthBeta)
		headers.Set("User-Agent", claudeUsageUserAgent)
		body, errGet := p.get(ctx, cfg, auth, claudeUsageURL, headers)
		if errGet != nil {
			return snapshot, errGet
		}
		parseClaudeUsage(body, &snapshot)
	case "codex":
		headers.Set("User-Agent", codexUsageUserAgent)
		if accountID := metadataString(auth, "account_id"); accountID != "" {
			headers.Set("ChatGPT-Account-Id", accountID)
		}
		body, errGet := p.get(ctx, cfg, auth, codexUsageURL, headers)
		if errGet != nil {
			return snapshot, errGet
		}
		parseCodexUsage(body, &snapshot)
		// Banked resets are a bonus; a failure here must not discard the usage.
		if credits, errCredits := p.get(ctx, cfg, auth, codexResetCreditsURL, headers); errCredits == nil {
			snapshot.ResetCreditExpiries = parseCodexResetCredits(credits)
		} else {
			log.Debugf("usage routing: reset credits for %s: %v", auth.ID, errCredits)
		}
	}
	snapshot.FetchedAt = p.now().UTC()
	return snapshot, nil
}

func (p *Poller) get(ctx context.Context, cfg *config.Config, auth *coreauth.Auth, url string, headers http.Header) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, errReq := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if errReq != nil {
		return nil, errReq
	}
	req.Header = headers.Clone()
	resp, errDo := p.client(reqCtx, cfg, auth).Do(req)
	if errDo != nil {
		return nil, errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("usage routing: close body: %v", errClose)
		}
	}()
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if errRead != nil {
		return nil, errRead
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return body, nil
}

// parseClaudeUsage reads /api/oauth/usage: five_hour and seven_day carry
// utilization (percent) and resets_at (RFC 3339).
func parseClaudeUsage(body []byte, snapshot *coreauth.UsageSnapshot) {
	snapshot.Primary = claudeWindow(ojson.GetBytes(body, "five_hour"), 5*3600)
	snapshot.Secondary = claudeWindow(ojson.GetBytes(body, "seven_day"), 7*24*3600)
	snapshot.ExtraUsageEnabled = ojson.GetBytes(body, "extra_usage.is_enabled").Bool()
}

func claudeWindow(node ojson.Result, windowSeconds int64) *coreauth.UsageWindow {
	if !node.IsObject() || !node.Get("utilization").Exists() {
		return nil
	}
	window := &coreauth.UsageWindow{UsedPercent: node.Get("utilization").Float(), WindowSeconds: windowSeconds}
	if raw := strings.TrimSpace(node.Get("resets_at").String()); raw != "" {
		if parsed, errParse := time.Parse(time.RFC3339Nano, raw); errParse == nil {
			window.ResetAt = parsed.UTC()
		}
	}
	return window
}

// parseCodexUsage reads wham/usage: rate_limit.{allowed,limit_reached} and
// primary/secondary windows with used_percent and reset_at (unix seconds).
func parseCodexUsage(body []byte, snapshot *coreauth.UsageSnapshot) {
	rateLimit := ojson.GetBytes(body, "rate_limit")
	if !rateLimit.IsObject() {
		return
	}
	allowed := rateLimit.Get("allowed")
	snapshot.LimitReached = rateLimit.Get("limit_reached").Bool() || (allowed.Exists() && !allowed.Bool())
	snapshot.Primary = codexWindow(rateLimit.Get("primary_window"))
	snapshot.Secondary = codexWindow(rateLimit.Get("secondary_window"))
}

func codexWindow(node ojson.Result) *coreauth.UsageWindow {
	if !node.IsObject() {
		return nil
	}
	window := &coreauth.UsageWindow{UsedPercent: node.Get("used_percent").Float(), WindowSeconds: node.Get("limit_window_seconds").Int()}
	if resetAt := node.Get("reset_at").Int(); resetAt > 0 {
		window.ResetAt = time.Unix(resetAt, 0).UTC()
	}
	return window
}

// parseCodexResetCredits returns expiries of available banked resets.
func parseCodexResetCredits(body []byte) []time.Time {
	var expiries []time.Time
	for _, credit := range ojson.GetBytes(body, "credits").Array() {
		if credit.Get("status").String() != "available" {
			continue
		}
		raw := strings.TrimSpace(credit.Get("expires_at").String())
		if parsed, errParse := time.Parse(time.RFC3339Nano, raw); errParse == nil {
			expiries = append(expiries, parsed.UTC())
		}
	}
	return expiries
}

func describeWindow(w *coreauth.UsageWindow) string {
	if w == nil {
		return "-"
	}
	return fmt.Sprintf("%.0f%%@%s", w.UsedPercent, w.ResetAt.Format(time.RFC3339))
}

// loadState restores cached snapshots and retained history once per process.
func (p *Poller) loadState(cacheFile string) {
	p.loadCache(cacheFile)
	p.loadHistory(historyFile(cacheFile))
}

func (p *Poller) loadCache(path string) {
	if path == "" {
		return
	}
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		if !os.IsNotExist(errRead) {
			log.Warnf("usage routing: read cache %s: %v", path, errRead)
		}
		return
	}
	var snapshots []coreauth.UsageSnapshot
	if errDecode := json.Unmarshal(data, &snapshots); errDecode != nil {
		log.Warnf("usage routing: decode cache %s: %v", path, errDecode)
		return
	}
	for _, snapshot := range snapshots {
		coreauth.StoreUsageSnapshot(snapshot)
	}
	log.Infof("usage routing: loaded %d cached usage snapshots", len(snapshots))
}

func (p *Poller) saveCache(path string) {
	if path == "" {
		return
	}
	data, errEncode := json.MarshalIndent(coreauth.UsageSnapshots(), "", "  ")
	if errEncode != nil {
		log.Warnf("usage routing: encode cache: %v", errEncode)
		return
	}
	tmp := path + ".tmp"
	if errWrite := os.WriteFile(tmp, data, 0o600); errWrite != nil {
		log.Warnf("usage routing: write cache %s: %v", tmp, errWrite)
		return
	}
	if errRename := os.Rename(tmp, path); errRename != nil {
		log.Warnf("usage routing: replace cache %s: %v", path, errRename)
	}
}
