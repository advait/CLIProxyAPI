package auth

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Usage-aware routing (fork addition).
//
// A background poller (internal/usagerouting) stores one UsageSnapshot per
// credential. UsageAwareSelector uses the snapshots to choose the credential for
// cold session bindings, and isAuthBlockedForModelForRequest treats a credential
// whose snapshot shows an exhausted limit as cooling down until the window resets.
// Because that availability check also guards established bindings, sessions bound
// to an exhausted credential fail over instead of spending paid overage.

// UsageWindow is one rate-limit window of a subscription.
type UsageWindow struct {
	UsedPercent float64   `json:"used_percent"`
	ResetAt     time.Time `json:"reset_at,omitempty"`
}

// remaining reports percent headroom, treating an elapsed reset as a fresh window
// and a missing window as unconstrained.
func (w *UsageWindow) remaining(now time.Time) float64 {
	if w == nil {
		return 100
	}
	if !w.ResetAt.IsZero() && !now.Before(w.ResetAt) {
		return 100
	}
	return math.Max(0, 100-w.UsedPercent)
}

// exhaustedUntil reports whether the window is at its limit and when it resets.
func (w *UsageWindow) exhaustedUntil(now time.Time) (time.Time, bool) {
	if w == nil || w.UsedPercent < 100 || w.ResetAt.IsZero() || !now.Before(w.ResetAt) {
		return time.Time{}, false
	}
	return w.ResetAt, true
}

// UsageSnapshot is the cached usage state of one credential.
type UsageSnapshot struct {
	AuthID    string    `json:"auth_id"`
	Provider  string    `json:"provider"`
	Email     string    `json:"email,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
	// Primary is the short window (Claude five_hour, Codex primary_window).
	Primary *UsageWindow `json:"primary,omitempty"`
	// Secondary is the long window (Claude seven_day, Codex secondary_window).
	Secondary *UsageWindow `json:"secondary,omitempty"`
	// LimitReached is the provider's explicit hard-limit flag (Codex).
	LimitReached bool `json:"limit_reached,omitempty"`
	// ResetCreditExpiries lists expiries of available banked resets (Codex).
	ResetCreditExpiries []time.Time `json:"reset_credit_expiries,omitempty"`
	// ExtraUsageEnabled reports paid overage (Claude). Informational only: exhausted
	// credentials are never selected regardless.
	ExtraUsageEnabled bool `json:"extra_usage_enabled,omitempty"`
}

// UsageWeights tunes the usage score.
type UsageWeights struct {
	Primary     float64
	Secondary   float64
	ResetCredit float64
}

// DefaultUsageWeights mirrors codex-profiles' scoring.
func DefaultUsageWeights() UsageWeights {
	return UsageWeights{Primary: 1000, Secondary: 1, ResetCredit: 100_000}
}

// ExhaustedUntil reports whether the snapshot shows a hit limit and when the
// credential becomes usable again.
func (s *UsageSnapshot) ExhaustedUntil(now time.Time, fallbackRetry time.Duration) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	var until time.Time
	for _, w := range []*UsageWindow{s.Primary, s.Secondary} {
		if reset, ok := w.exhaustedUntil(now); ok && reset.After(until) {
			until = reset
		}
	}
	if !until.IsZero() {
		return until, true
	}
	if s.LimitReached {
		// Flagged without a usable reset time: re-check after the next poll.
		return s.FetchedAt.Add(fallbackRetry), s.FetchedAt.Add(fallbackRetry).After(now)
	}
	return time.Time{}, false
}

// Score ranks a snapshot: weighted headroom plus a bonus per banked reset that
// grows as the reset nears expiry (weight/(1+timeLeft/7d)). Exhausted snapshots
// score below zero, soonest reset highest.
func (s *UsageSnapshot) Score(now time.Time, weights UsageWeights, fallbackRetry time.Duration) float64 {
	if until, exhausted := s.ExhaustedUntil(now, fallbackRetry); exhausted {
		return -until.Sub(now).Hours()
	}
	score := weights.Primary*s.Primary.remaining(now) + weights.Secondary*s.Secondary.remaining(now)
	const scale = float64(7 * 24 * time.Hour)
	for _, expiry := range s.ResetCreditExpiries {
		if left := expiry.Sub(now); left > 0 {
			score += weights.ResetCredit / (1 + float64(left)/scale)
		}
	}
	return score
}

type usageRoutingState struct {
	mu         sync.RWMutex
	enabled    bool
	weights    UsageWeights
	staleAfter time.Duration
	retryAfter time.Duration
	snapshots  map[string]UsageSnapshot
	nowFunc    func() time.Time
}

var usageRouting = &usageRoutingState{
	weights:    DefaultUsageWeights(),
	staleAfter: 15 * time.Minute,
	retryAfter: 5 * time.Minute,
	snapshots:  make(map[string]UsageSnapshot),
	nowFunc:    time.Now,
}

// ConfigureUsageRouting enables or disables usage-aware availability checks and
// sets the scoring weights. pollInterval drives staleness (3x) and the re-check
// delay for limit flags without a reset time.
func ConfigureUsageRouting(enabled bool, weights UsageWeights, pollInterval time.Duration) {
	usageRouting.mu.Lock()
	defer usageRouting.mu.Unlock()
	usageRouting.enabled = enabled
	usageRouting.weights = weights
	if pollInterval > 0 {
		usageRouting.staleAfter = 3 * pollInterval
		usageRouting.retryAfter = pollInterval
	}
}

// UsageRoutingEnabled reports whether the usage-aware strategy is active.
func UsageRoutingEnabled() bool {
	usageRouting.mu.RLock()
	defer usageRouting.mu.RUnlock()
	return usageRouting.enabled
}

// StoreUsageSnapshot records the latest usage for a credential.
func StoreUsageSnapshot(snapshot UsageSnapshot) {
	if snapshot.AuthID == "" {
		return
	}
	usageRouting.mu.Lock()
	usageRouting.snapshots[snapshot.AuthID] = snapshot
	usageRouting.mu.Unlock()
}

// ForgetUsageSnapshot drops a credential's cached usage.
func ForgetUsageSnapshot(authID string) {
	usageRouting.mu.Lock()
	delete(usageRouting.snapshots, authID)
	usageRouting.mu.Unlock()
}

// UsageSnapshots returns all cached snapshots sorted by auth ID.
func UsageSnapshots() []UsageSnapshot {
	usageRouting.mu.RLock()
	out := make([]UsageSnapshot, 0, len(usageRouting.snapshots))
	for _, snapshot := range usageRouting.snapshots {
		out = append(out, snapshot)
	}
	usageRouting.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].AuthID < out[j].AuthID })
	return out
}

// UsageRoutingStatus is one row of the usage routing report.
type UsageRoutingStatus struct {
	UsageSnapshot
	Score          float64    `json:"score"`
	Stale          bool       `json:"stale"`
	ExhaustedUntil *time.Time `json:"exhausted_until,omitempty"`
}

// UsageRoutingReport returns snapshots with their current score and availability.
func UsageRoutingReport() []UsageRoutingStatus {
	usageRouting.mu.RLock()
	now := usageRouting.nowFunc()
	weights, staleAfter, retryAfter := usageRouting.weights, usageRouting.staleAfter, usageRouting.retryAfter
	usageRouting.mu.RUnlock()
	snapshots := UsageSnapshots()
	out := make([]UsageRoutingStatus, 0, len(snapshots))
	for i := range snapshots {
		s := &snapshots[i]
		row := UsageRoutingStatus{UsageSnapshot: *s, Score: s.Score(now, weights, retryAfter), Stale: now.Sub(s.FetchedAt) > staleAfter}
		if until, ok := s.ExhaustedUntil(now, retryAfter); ok {
			row.ExhaustedUntil = &until
		}
		out = append(out, row)
	}
	return out
}

// freshUsageSnapshot returns the credential's snapshot when routing is enabled and
// the snapshot is not stale. Stale data never blocks or ranks a credential.
func freshUsageSnapshot(authID string) (UsageSnapshot, UsageWeights, time.Duration, time.Time, bool) {
	usageRouting.mu.RLock()
	defer usageRouting.mu.RUnlock()
	now := usageRouting.nowFunc()
	if !usageRouting.enabled {
		return UsageSnapshot{}, UsageWeights{}, 0, now, false
	}
	snapshot, ok := usageRouting.snapshots[authID]
	if !ok || now.Sub(snapshot.FetchedAt) > usageRouting.staleAfter {
		return UsageSnapshot{}, UsageWeights{}, 0, now, false
	}
	return snapshot, usageRouting.weights, usageRouting.retryAfter, now, true
}

// usageExhaustedUntil is consulted by the availability check.
func usageExhaustedUntil(auth *Auth, now time.Time) (time.Time, bool) {
	if auth == nil {
		return time.Time{}, false
	}
	snapshot, _, retryAfter, _, ok := freshUsageSnapshot(auth.ID)
	if !ok {
		return time.Time{}, false
	}
	return snapshot.ExhaustedUntil(now, retryAfter)
}

// UsageAwareSelector binds new sessions to the available credential with the best
// usage score. Credentials without fresh usage data rank below any credential with
// known headroom; ties (including all-unknown) rotate round-robin.
type UsageAwareSelector struct {
	tie RoundRobinSelector
}

// Pick implements Selector.
func (s *UsageAwareSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, time.Now())
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	best := bestUsageAuths(available)
	if len(best) == 1 {
		return best[0], nil
	}
	return s.tie.Pick(context.WithValue(ctx, prevalidatedAuthCandidatesKey{}, true), provider, model, opts, best)
}

// bestUsageAuths returns the highest-scoring candidates. Unknown usage scores 0,
// below any credential with headroom but above exhausted ones (which are normally
// filtered out by the availability check already).
func bestUsageAuths(auths []*Auth) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	const epsilon = 1e-6
	bestScore := math.Inf(-1)
	var best []*Auth
	for _, candidate := range auths {
		score := 0.0
		if snapshot, weights, retryAfter, now, ok := freshUsageSnapshot(candidate.ID); ok {
			score = snapshot.Score(now, weights, retryAfter)
		}
		switch {
		case score > bestScore+epsilon:
			bestScore = score
			best = append(best[:0], candidate)
		case math.Abs(score-bestScore) <= epsilon:
			best = append(best, candidate)
		}
	}
	return best
}
