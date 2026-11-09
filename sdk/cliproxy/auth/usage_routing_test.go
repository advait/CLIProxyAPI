package auth

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// withUsageRouting enables usage routing with a fixed clock and restores the
// global state after the test.
func withUsageRouting(t *testing.T, now time.Time) {
	t.Helper()
	usageRouting.mu.Lock()
	saved := struct {
		enabled                bool
		weights                UsageWeights
		staleAfter, retryAfter time.Duration
		snapshots              map[string]UsageSnapshot
		history                []UsageSample
		nowFunc                func() time.Time
	}{usageRouting.enabled, usageRouting.weights, usageRouting.staleAfter, usageRouting.retryAfter, usageRouting.snapshots, usageRouting.history, usageRouting.nowFunc}
	usageRouting.enabled = true
	usageRouting.weights = DefaultUsageWeights()
	usageRouting.staleAfter = 15 * time.Minute
	usageRouting.retryAfter = 5 * time.Minute
	usageRouting.snapshots = make(map[string]UsageSnapshot)
	usageRouting.nowFunc = func() time.Time { return now }
	usageRouting.mu.Unlock()
	t.Cleanup(func() {
		usageRouting.mu.Lock()
		usageRouting.enabled = saved.enabled
		usageRouting.weights = saved.weights
		usageRouting.staleAfter = saved.staleAfter
		usageRouting.retryAfter = saved.retryAfter
		usageRouting.snapshots = saved.snapshots
		usageRouting.history = saved.history
		usageRouting.nowFunc = saved.nowFunc
		usageRouting.mu.Unlock()
	})
}

func TestUsageSnapshotScoreMatchesCodexProfiles(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	snapshot := UsageSnapshot{
		FetchedAt:           now,
		Primary:             &UsageWindow{UsedPercent: 12, ResetAt: now.Add(39 * time.Hour)},
		Secondary:           &UsageWindow{UsedPercent: 40, ResetAt: now.Add(72 * time.Hour)},
		ResetCreditExpiries: []time.Time{now.Add(7 * 24 * time.Hour), now.Add(-time.Hour)},
	}
	// 88*1000 + 60 + 100000/(1+1) for the one unexpired credit.
	want := 88.0*1000 + 60 + 50_000
	if got := snapshot.Score(now, DefaultUsageWeights(), 5*time.Minute); math.Abs(got-want) > 1e-6 {
		t.Fatalf("Score = %v, want %v", got, want)
	}
	// A missing window is unconstrained and an elapsed reset is a fresh window.
	fresh := UsageSnapshot{Secondary: &UsageWindow{UsedPercent: 100, ResetAt: now.Add(-time.Minute)}}
	if got := fresh.Score(now, DefaultUsageWeights(), 5*time.Minute); got != 100*1000+100 {
		t.Fatalf("fresh Score = %v, want %v", got, 100*1000+100)
	}
}

func TestUsageSnapshotExhaustion(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	reset := now.Add(3 * time.Hour)
	claude := UsageSnapshot{FetchedAt: now, Secondary: &UsageWindow{UsedPercent: 100, ResetAt: reset}, ExtraUsageEnabled: true}
	until, exhausted := claude.ExhaustedUntil(now, 5*time.Minute)
	if !exhausted || !until.Equal(reset) {
		t.Fatalf("ExhaustedUntil = %v,%v want %v,true (extra usage must not count as headroom)", until, exhausted, reset)
	}
	if claude.Score(now, DefaultUsageWeights(), 5*time.Minute) >= 0 {
		t.Fatal("exhausted snapshot must score below zero")
	}
	flagged := UsageSnapshot{FetchedAt: now, LimitReached: true}
	if until, exhausted = flagged.ExhaustedUntil(now, 5*time.Minute); !exhausted || !until.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("flag without reset: ExhaustedUntil = %v,%v", until, exhausted)
	}
	if _, exhausted = flagged.ExhaustedUntil(now.Add(6*time.Minute), 5*time.Minute); exhausted {
		t.Fatal("flag without reset must expire after the retry delay")
	}
}

func TestUsageAwareSelectorPicksBestScoreAndRotatesTies(t *testing.T) {
	now := time.Now()
	withUsageRouting(t, now)
	auths := []*Auth{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	StoreUsageSnapshot(UsageSnapshot{AuthID: "a", FetchedAt: now, Primary: &UsageWindow{UsedPercent: 50}})
	StoreUsageSnapshot(UsageSnapshot{AuthID: "b", FetchedAt: now, Primary: &UsageWindow{UsedPercent: 10}})
	selector := &UsageAwareSelector{}
	for i := 0; i < 3; i++ {
		got, errPick := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
		if errPick != nil || got.ID != "b" {
			t.Fatalf("Pick = %v,%v want b", got, errPick)
		}
	}
	// Stale data is ignored: with every snapshot stale all three tie and rotate.
	withUsageRouting(t, now.Add(time.Hour))
	StoreUsageSnapshot(UsageSnapshot{AuthID: "b", FetchedAt: now, Primary: &UsageWindow{UsedPercent: 10}})
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		got, errPick := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick: %v", errPick)
		}
		seen[got.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("ties should rotate across all candidates, saw %v", seen)
	}
}

func TestUsageAwareSelectorIgnoresDisabledRouting(t *testing.T) {
	now := time.Now()
	withUsageRouting(t, now)
	StoreUsageSnapshot(UsageSnapshot{AuthID: "a", FetchedAt: now, Secondary: &UsageWindow{UsedPercent: 100, ResetAt: now.Add(time.Hour)}})
	usageRouting.mu.Lock()
	usageRouting.enabled = false
	usageRouting.mu.Unlock()
	if blocked, _, _ := isAuthBlockedForModel(&Auth{ID: "a", Status: StatusActive}, "", now); blocked {
		t.Fatal("usage data must not block credentials when usage routing is disabled")
	}
}

func TestManagerUsageAwareFailsOverBoundSessionWhenExhausted(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	withUsageRouting(t, now)
	provider := "usage-aware-failover"
	model := "usage-aware-model"
	personal, work := provider+"-personal", provider+"-work"

	manager := NewManager(nil, nil, nil)
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &UsageAwareSelector{},
		TTL:      time.Hour,
		RebindOn: SessionAffinityRebindOnQuota,
	})
	defer affinity.Stop()
	manager.SetSelector(affinity)
	manager.RegisterExecutor(schedulerTestExecutor{provider: provider})
	for _, id := range []string{personal, work} {
		if _, errRegister := manager.Register(WithSkipPersist(ctx), &Auth{ID: id, Provider: provider, Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s): %v", id, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
		authID := id
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
	}
	StoreUsageSnapshot(UsageSnapshot{AuthID: personal, FetchedAt: now, Secondary: &UsageWindow{UsedPercent: 5, ResetAt: now.Add(48 * time.Hour)}})
	StoreUsageSnapshot(UsageSnapshot{AuthID: work, FetchedAt: now, Secondary: &UsageWindow{UsedPercent: 70, ResetAt: now.Add(48 * time.Hour)}})

	pick := func(session string) (*Auth, error) {
		opts := cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.DerivedSessionIDMetadataKey: session}}
		auth, _, _, errPick := manager.pickNextMixed(ctx, []string{provider}, model, opts, nil)
		return auth, errPick
	}
	mustPick := func(session, want string) {
		t.Helper()
		got, errPick := pick(session)
		if errPick != nil || got == nil || got.ID != want {
			t.Fatalf("pick(%s) = %v,%v want %s", session, got, errPick, want)
		}
	}

	mustPick("s1", personal) // cold binding goes to the best score
	// Work gains headroom: the bound session stays put, new sessions follow the score.
	StoreUsageSnapshot(UsageSnapshot{AuthID: work, FetchedAt: now, Secondary: &UsageWindow{UsedPercent: 0, ResetAt: now.Add(48 * time.Hour)}})
	StoreUsageSnapshot(UsageSnapshot{AuthID: personal, FetchedAt: now, Secondary: &UsageWindow{UsedPercent: 50, ResetAt: now.Add(48 * time.Hour)}})
	mustPick("s1", personal)
	mustPick("s2", work)
	// Personal exhausts: its bound session fails over rather than using overage.
	StoreUsageSnapshot(UsageSnapshot{AuthID: personal, FetchedAt: now, Secondary: &UsageWindow{UsedPercent: 100, ResetAt: now.Add(2 * time.Hour)}, ExtraUsageEnabled: true})
	mustPick("s1", work)
	// Everything exhausted: selection fails instead of spending overage.
	StoreUsageSnapshot(UsageSnapshot{AuthID: work, FetchedAt: now, Secondary: &UsageWindow{UsedPercent: 100, ResetAt: now.Add(time.Hour)}})
	if got, errPick := pick("s3"); errPick == nil {
		t.Fatalf("pick with all credentials exhausted = %v, want error", got)
	}
}

func TestUsageHistoryRetentionAndSince(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	withUsageRouting(t, now)
	usageRouting.mu.Lock()
	usageRouting.history = nil
	usageRouting.mu.Unlock()
	used := 40.0
	AppendUsageHistory(
		UsageSample{At: now.Add(-UsageHistoryRetention - time.Hour), AuthID: "old", Primary: &used},
		UsageSample{At: now.Add(-2 * time.Hour), AuthID: "a", Primary: &used},
		SampleFromSnapshot(UsageSnapshot{AuthID: "b", FetchedAt: now, Secondary: &UsageWindow{UsedPercent: 12}}),
	)
	all := UsageHistory(time.Time{})
	if len(all) != 2 || all[0].AuthID != "a" || all[1].Secondary == nil || *all[1].Secondary != 12 || all[1].Primary != nil {
		t.Fatalf("history = %+v, want expired sample dropped", all)
	}
	if recent := UsageHistory(now.Add(-time.Hour)); len(recent) != 1 || recent[0].AuthID != "b" {
		t.Fatalf("since filter = %+v", recent)
	}
}
