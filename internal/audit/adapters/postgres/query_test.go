package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/adapters/postgres/pgtest"
	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

func TestFindEvent(t *testing.T) {
	store, _ := setupStore(t)
	ctx := context.Background()
	recs := []domain.Record{record(t, 1, nil), record(t, 2, func(in *domain.EventInput) {
		in.SourceIP, in.ActorID, in.ActorType = "", "", ""
		in.Payload = []byte(`{"n": 12345678901234567890, "a": [1, 2]}`)
	})}
	if _, err := store.Append(ctx, recs); err != nil {
		t.Fatal(err)
	}

	got, err := store.FindEvent(ctx, recs[1].EventID)
	if err != nil {
		t.Fatalf("FindEvent: %v", err)
	}
	if got.ID != 2 || got.EventID != recs[1].EventID || got.ActorID != "" || got.SourceIP != "" {
		t.Errorf("FindEvent = %+v, want the second record with no actor or IP", got)
	}
	if string(got.Payload) != `{"a": [1, 2], "n": 12345678901234567890}` {
		t.Errorf("payload = %s, want the stored jsonb text", got.Payload)
	}
	if got.Hash != domain.ComputeHash(got.PrevHash, got.Record) {
		t.Error("returned record does not match its own hash")
	}

	_, err = store.FindEvent(ctx, "11111111-2222-4333-8444-555555555555")
	if !errors.Is(err, ports.ErrEventNotFound) {
		t.Errorf("FindEvent(unknown) error = %v, want ErrEventNotFound", err)
	}
}

// listFixture stores 12 events spread over three hours, with several sharing occurred_at so
// pagination has to break ties by id.
func listFixture(t *testing.T) (*EventStore, time.Time) {
	t.Helper()
	store, _ := setupStore(t)
	base := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	types := []string{"auth.login_failed", "access.denied", "data.export"}
	sevs := []string{"LOW", "HIGH", "CRITICAL", "INFO"}
	var recs []domain.Record
	for i := 1; i <= 12; i++ {
		recs = append(recs, record(t, i, func(in *domain.EventInput) {
			in.EventType = types[i%3]
			in.Severity = sevs[i%4]
			in.ActorID = fmt.Sprintf("user-%d", i%2)
			in.OccurredAt = base.Add(time.Duration(i/3) * time.Hour).Format(time.RFC3339Nano)
		}))
	}
	if _, err := store.Append(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	return store, base
}

func eventNumbers(events []ports.StoredEvent) []int64 {
	ids := make([]int64, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	return ids
}

func TestListEventsFilters(t *testing.T) {
	store, base := listFixture(t)
	ctx := context.Background()
	high := domain.SeverityHigh
	all := ports.EventFilter{From: base.Add(-time.Hour), To: base.Add(5 * time.Hour), Limit: 100}
	with := func(edit func(*ports.EventFilter)) ports.EventFilter {
		f := all
		edit(&f)
		return f
	}

	tests := []struct {
		name string
		f    ports.EventFilter
		want []int64
	}{
		// Order is occurred_at DESC, id DESC. Event i occurs at base + i/3 hours.
		{"everything", all, []int64{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}},
		{"event_type", with(func(f *ports.EventFilter) { f.EventType = "access.denied" }), []int64{10, 7, 4, 1}},
		{"severity", with(func(f *ports.EventFilter) { f.Severity = &high }), []int64{9, 5, 1}},
		{"actor_id", with(func(f *ports.EventFilter) { f.ActorID = "user-0" }), []int64{12, 10, 8, 6, 4, 2}},
		{"source_module", with(func(f *ports.EventFilter) { f.SourceModule = "IAM" }), []int64{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}},
		{"other source_module", with(func(f *ports.EventFilter) { f.SourceModule = "LAB" }), []int64{}},
		{"from inclusive", with(func(f *ports.EventFilter) { f.From = base.Add(3 * time.Hour) }), []int64{12, 11, 10, 9}},
		{"to inclusive", with(func(f *ports.EventFilter) { f.To = base }), []int64{2, 1}},
		{"combined", with(func(f *ports.EventFilter) {
			f.EventType, f.ActorID, f.From = "access.denied", "user-0", base.Add(time.Hour)
		}), []int64{10, 4}},
		{"injection in actor_id", with(func(f *ports.EventFilter) { f.ActorID = "' OR 1=1--" }), []int64{}},
		{"injection in event_type", with(func(f *ports.EventFilter) { f.EventType = "x' OR '1'='1" }), []int64{}},
		{"limit", with(func(f *ports.EventFilter) { f.Limit = 2 }), []int64{12, 11}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.ListEvents(ctx, tt.f)
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			if ids := eventNumbers(got); !slices.Equal(ids, tt.want) {
				t.Errorf("ids = %v, want %v", ids, tt.want)
			}
		})
	}
}

func TestListEventsKeysetWalksEveryEventOnce(t *testing.T) {
	store, base := listFixture(t)
	ctx := context.Background()
	f := ports.EventFilter{From: base.Add(-time.Hour), To: base.Add(5 * time.Hour), Limit: 5}

	var walked []int64
	for page := 0; page < 10; page++ {
		got, err := store.ListEvents(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		walked = append(walked, eventNumbers(got)...)
		if len(got) < f.Limit {
			break
		}
		last := got[len(got)-1]
		f.After = &ports.Cursor{OccurredAt: last.OccurredAt, ID: last.ID}
	}
	if want := []int64{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}; !slices.Equal(walked, want) {
		t.Errorf("walked %v, want %v", walked, want)
	}
}

func TestSuspiciousStats(t *testing.T) {
	store, pool := setupStore(t)
	ctx := context.Background()
	at := func(hhmm string) string { return "2026-10-25T" + hhmm + ":00Z" }
	type ev struct{ typ, sev, when, actor, ip string }
	events := []ev{
		// Failed logins: 3 at 10h, 2 at 12h, 1 before the range.
		{"auth.login_failed", "LOW", at("10:05"), "u1", ""},
		{"auth.login_failed", "LOW", at("10:20"), "u1", ""},
		{"auth.login_failed", "MEDIUM", at("10:59"), "u2", ""},
		{"auth.login_failed", "LOW", at("12:30"), "u3", ""},
		{"auth.login_failed", "LOW", at("12:31"), "u3", ""},
		{"auth.login_failed", "LOW", at("09:59"), "u1", ""},
		// Denied accesses: user-a 3, no actor 2, user-b 1, plus one after the range.
		{"access.denied", "MEDIUM", at("10:10"), "user-a", ""},
		{"access.denied", "MEDIUM", at("11:10"), "user-a", ""},
		{"access.denied", "MEDIUM", at("12:10"), "user-a", ""},
		{"access.denied", "MEDIUM", at("11:00"), "user-b", ""},
		{"access.denied", "LOW", at("11:30"), "", ""},
		{"access.denied", "LOW", at("11:40"), "", ""},
		{"access.denied", "MEDIUM", at("13:01"), "user-b", ""},
		// HIGH/CRITICAL by IP: 203.0.113.5 x3, 2001:db8::1 x2, 198.51.100.7 x1; MEDIUM and IP-less ignored.
		{"access.idor_attempt", "HIGH", at("10:30"), "x", "203.0.113.5"},
		{"access.idor_attempt", "CRITICAL", at("10:31"), "x", "203.0.113.5"},
		{"data.export", "HIGH", at("10:32"), "x", "203.0.113.5"},
		{"data.export", "MEDIUM", at("10:33"), "x", "203.0.113.5"},
		{"auth.account_locked", "HIGH", at("11:00"), "y", "2001:db8::1"},
		{"auth.account_locked", "HIGH", at("11:01"), "y", "2001:db8::1"},
		{"security.config_changed", "CRITICAL", at("12:00"), "z", "198.51.100.7"},
		{"security.config_changed", "CRITICAL", at("12:01"), "z", ""},
	}
	recs := make([]domain.Record, len(events))
	for i, e := range events {
		recs[i] = record(t, i+1, func(in *domain.EventInput) {
			in.EventType, in.Severity, in.OccurredAt, in.ActorID, in.SourceIP = e.typ, e.sev, e.when, e.actor, e.ip
			if e.actor == "" {
				in.ActorType = ""
			}
		})
	}
	if _, err := store.Append(ctx, recs); err != nil {
		t.Fatal(err)
	}

	from, to := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC), time.Date(2026, 10, 25, 13, 0, 0, 0, time.UTC)
	got, err := store.SuspiciousStats(ctx, from, to, 10)
	if err != nil {
		t.Fatalf("SuspiciousStats: %v", err)
	}

	hours := []ports.HourCount{{Hour: from, Count: 3}, {Hour: from.Add(2 * time.Hour), Count: 2}}
	actors := []ports.ActorCount{{ActorID: "user-a", Count: 3}, {ActorID: "", Count: 2}, {ActorID: "user-b", Count: 1}}
	ips := []ports.IPCount{{IP: "203.0.113.5", Count: 3}, {IP: "2001:db8::1", Count: 2}, {IP: "198.51.100.7", Count: 1}}
	if !slices.EqualFunc(got.FailedLoginsPerHour, hours, func(a, b ports.HourCount) bool { return a.Hour.Equal(b.Hour) && a.Count == b.Count }) {
		t.Errorf("FailedLoginsPerHour = %v, want %v", got.FailedLoginsPerHour, hours)
	}
	if !slices.Equal(got.DeniedByActor, actors) {
		t.Errorf("DeniedByActor = %v, want %v", got.DeniedByActor, actors)
	}
	if !slices.Equal(got.TopIPs, ips) {
		t.Errorf("TopIPs = %v, want %v", got.TopIPs, ips)
	}

	// Cross-check against plain SQL written independently of the store.
	var logins, denied, highIPs int64
	if err := pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE event_type = 'auth.login_failed'),
		count(*) FILTER (WHERE event_type = 'access.denied'),
		count(*) FILTER (WHERE severity >= 3 AND source_ip IS NOT NULL)
		FROM audit_logs WHERE occurred_at BETWEEN $1 AND $2`, from, to).Scan(&logins, &denied, &highIPs); err != nil {
		t.Fatal(err)
	}
	sum := func(n ...int64) (s int64) {
		for _, v := range n {
			s += v
		}
		return s
	}
	var h, a, i []int64
	for _, x := range got.FailedLoginsPerHour {
		h = append(h, x.Count)
	}
	for _, x := range got.DeniedByActor {
		a = append(a, x.Count)
	}
	for _, x := range got.TopIPs {
		i = append(i, x.Count)
	}
	if sum(h...) != logins || sum(a...) != denied || sum(i...) != highIPs {
		t.Errorf("totals = %d/%d/%d, plain SQL = %d/%d/%d", sum(h...), sum(a...), sum(i...), logins, denied, highIPs)
	}

	top1, err := store.SuspiciousStats(ctx, from, to, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(top1.DeniedByActor) != 1 || len(top1.TopIPs) != 1 || len(top1.FailedLoginsPerHour) != 2 {
		t.Errorf("top=1: %+v, want one actor, one IP and every hour", top1)
	}
}

func TestVerifyChainRange(t *testing.T) {
	db := pgtest.Start(t)
	ctx := context.Background()
	owner := pgtest.Pool(t, db.OwnerURL)
	if _, err := owner.Exec(ctx, `INSERT INTO api_clients (client_id, module_code, secret_enc) VALUES ($1, 'IAM', '\x00')`, testClient); err != nil {
		t.Fatal(err)
	}
	store := NewEventStore(pgtest.Pool(t, db.AppURL))
	var recs []domain.Record
	for i := 1; i <= 6; i++ {
		recs = append(recs, record(t, i, nil))
	}
	if _, err := store.Append(ctx, recs); err != nil {
		t.Fatal(err)
	}
	asOwner := func(sqls ...string) {
		t.Helper()
		for _, sql := range sqls {
			if _, err := owner.Exec(ctx, sql); err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
		}
	}

	check := func(from, to int64, want ports.ChainReport) {
		t.Helper()
		got, err := store.VerifyChain(ctx, from, to)
		if err != nil {
			t.Fatalf("VerifyChain(%d, %d): %v", from, to, err)
		}
		if got.OK != want.OK || got.Checked != want.Checked || got.FirstBrokenID != want.FirstBrokenID || got.LastID != want.LastID {
			t.Errorf("VerifyChain(%d, %d) = %+v, want %+v", from, to, got, want)
		}
		if got.OK && got.LastID > 0 {
			var h []byte
			if err := owner.QueryRow(ctx, "SELECT hash FROM audit_logs WHERE id = $1", got.LastID).Scan(&h); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(h, got.LastHash[:]) {
				t.Errorf("LastHash = %x, want the stored hash of id %d (%x)", got.LastHash, got.LastID, h)
			}
		}
	}

	check(1, 6, ports.ChainReport{OK: true, Checked: 6, LastID: 6})
	check(3, 4, ports.ChainReport{OK: true, Checked: 2, LastID: 4})
	check(5, 1000, ports.ChainReport{OK: true, Checked: 2, LastID: 6})
	check(100, 200, ports.ChainReport{OK: true, Checked: 0})

	// Altering row 3 breaks it but not the links after it: 4 still points to 3's stored hash.
	asOwner("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update_delete",
		"UPDATE audit_logs SET actor_id = 'someone-else' WHERE id = 3")
	check(1, 6, ports.ChainReport{OK: false, Checked: 3, FirstBrokenID: 3})
	check(4, 6, ports.ChainReport{OK: true, Checked: 3, LastID: 6})

	// Deleting row 5 breaks the link of row 6, even when the range starts at 6.
	asOwner("DELETE FROM audit_logs WHERE id = 5")
	check(6, 6, ports.ChainReport{OK: false, Checked: 1, FirstBrokenID: 6})
	check(4, 6, ports.ChainReport{OK: false, Checked: 2, FirstBrokenID: 6})
}
