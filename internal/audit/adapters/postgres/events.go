package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

// chainLockKey identifies the transaction-level advisory lock that serializes every append,
// so two writers (even in different processes) never read the same tail.
const chainLockKey int64 = 0x4155445f43484149 // "AUD_CHAI" in ASCII

// recordColumns selects a row in the exact text forms the hash was computed over:
// host() drops the /32 or /128 netmask and payload::text is the jsonb normalized output.
const recordColumns = `id, event_id::text, client_id, source_module, event_type, severity,
	actor_id, actor_type, target_resource, host(source_ip), user_agent,
	occurred_at, received_at, payload::text, prev_hash, hash`

const insertRecord = `INSERT INTO audit_logs (
	event_id, client_id, source_module, event_type, severity,
	actor_id, actor_type, target_resource, source_ip, user_agent,
	occurred_at, received_at, payload, prev_hash, hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet, $10, $11, $12, $13::jsonb, $14, $15)`

// EventStore implements ports.EventStore on the audit_logs table.
type EventStore struct {
	pool *pgxpool.Pool
}

var _ ports.EventStore = (*EventStore)(nil)

// NewEventStore returns a store that connects with pool (as aud_app).
func NewEventStore(pool *pgxpool.Pool) *EventStore {
	return &EventStore{pool: pool}
}

// Append implements ports.EventStore. Errors caused by the data (SQLSTATE classes 22 and 23)
// wrap ports.ErrRejectedRecord.
func (s *EventStore) Append(ctx context.Context, records []domain.Record) (int, error) {
	n, err := s.append(ctx, records)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (strings.HasPrefix(pgErr.Code, "22") || strings.HasPrefix(pgErr.Code, "23")) {
		return 0, fmt.Errorf("%w: %w", ports.ErrRejectedRecord, err)
	}
	return n, err
}

func (s *EventStore) append(ctx context.Context, records []domain.Record) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", chainLockKey); err != nil {
		return 0, fmt.Errorf("lock chain: %w", err)
	}

	prev, err := chainTail(ctx, tx)
	if err != nil {
		return 0, err
	}
	seen, err := existingEventIDs(ctx, tx, records)
	if err != nil {
		return 0, err
	}
	forms, err := normalizeForms(ctx, tx, records)
	if err != nil {
		return 0, err
	}

	batch := &pgx.Batch{}
	for i, r := range records {
		if seen[r.EventID] {
			continue
		}
		seen[r.EventID] = true

		r.Payload = []byte(forms[i].Payload)
		r.SourceIP = deref(forms[i].SourceIP)
		r.Seal(prev)
		prev = r.Hash
		batch.Queue(insertRecord,
			r.EventID, r.ClientID, r.SourceModule, r.EventType, int16(r.Severity),
			nullable(r.ActorID), nullable(r.ActorType), nullable(r.TargetResource), nullable(r.SourceIP), nullable(r.UserAgent),
			r.OccurredAt, r.ReceivedAt, forms[i].Payload, r.PrevHash[:], r.Hash[:],
		)
	}
	inserted := batch.Len()
	if inserted == 0 {
		return 0, nil
	}

	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return 0, fmt.Errorf("insert records: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return inserted, nil
}

// ChainReport is the result of walking the hash chain.
type ChainReport struct {
	Checked       int64
	OK            bool
	FirstBrokenID int64 // id of the first row whose link or hash does not match; 0 when OK
}

// VerifyChain walks every record in id order, checking that each prev_hash points to the
// previous record and that each hash matches the stored columns.
func (s *EventStore) VerifyChain(ctx context.Context) (ChainReport, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+recordColumns+" FROM audit_logs ORDER BY id")
	if err != nil {
		return ChainReport{}, fmt.Errorf("read chain: %w", err)
	}
	defer rows.Close()

	report := ChainReport{OK: true}
	prev := domain.GenesisHash
	for rows.Next() {
		id, r, err := scanRecord(rows)
		if err != nil {
			return ChainReport{}, fmt.Errorf("read chain: %w", err)
		}
		report.Checked++
		if r.PrevHash != prev || r.Hash != domain.ComputeHash(r.PrevHash, r) {
			report.OK, report.FirstBrokenID = false, id
			return report, nil
		}
		prev = r.Hash
	}
	if err := rows.Err(); err != nil {
		return ChainReport{}, fmt.Errorf("read chain: %w", err)
	}
	return report, nil
}

// chainTail returns the hash of the last record, or the genesis hash for an empty table.
// The caller must hold the chain lock: ids are then assigned in chain order.
func chainTail(ctx context.Context, tx pgx.Tx) (domain.Hash, error) {
	var raw []byte
	err := tx.QueryRow(ctx, "SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1").Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.GenesisHash, nil
	}
	if err != nil {
		return domain.Hash{}, fmt.Errorf("read chain tail: %w", err)
	}
	return toHash(raw)
}

func existingEventIDs(ctx context.Context, tx pgx.Tx, records []domain.Record) (map[string]bool, error) {
	ids := make([]string, len(records))
	for i, r := range records {
		ids[i] = r.EventID
	}
	rows, err := tx.Query(ctx, "SELECT event_id::text FROM audit_logs WHERE event_id = ANY($1::uuid[])", ids)
	if err != nil {
		return nil, fmt.Errorf("find existing event ids: %w", err)
	}
	found, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("find existing event ids: %w", err)
	}
	seen := make(map[string]bool, len(records))
	for _, id := range found {
		seen[id] = true
	}
	return seen, nil
}

// storedForm is how PostgreSQL stores and prints the columns whose text Go cannot reproduce:
// jsonb reorders keys and respaces, and host(inet) writes ::/96 addresses as ::1.2.3.4.
type storedForm struct {
	Payload  string
	SourceIP *string
}

// normalizeForms returns the stored form of each record, in input order, so the hash covers
// exactly what a later verification reads back.
func normalizeForms(ctx context.Context, tx pgx.Tx, records []domain.Record) ([]storedForm, error) {
	payloads := make([]string, len(records))
	ips := make([]*string, len(records))
	for i, r := range records {
		payloads[i] = string(r.Payload)
		if r.SourceIP != "" {
			ips[i] = &r.SourceIP
		}
	}
	rows, err := tx.Query(ctx,
		`SELECT p::jsonb::text, host(ip::inet)
		   FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS t(p, ip, n) ORDER BY n`, payloads, ips)
	if err != nil {
		return nil, fmt.Errorf("normalize records: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[storedForm])
	if err != nil {
		return nil, fmt.Errorf("normalize records: %w", err)
	}
	return out, nil
}

// scanRecord reads a row selected with recordColumns.
func scanRecord(row pgx.Row) (int64, domain.Record, error) {
	var (
		id                                               int64
		r                                                domain.Record
		severity                                         int16
		actorID, actorType, targetResource, sourceIP, ua *string
		payload                                          string
		prevHash, hash                                   []byte
	)
	err := row.Scan(&id, &r.EventID, &r.ClientID, &r.SourceModule, &r.EventType, &severity,
		&actorID, &actorType, &targetResource, &sourceIP, &ua,
		&r.OccurredAt, &r.ReceivedAt, &payload, &prevHash, &hash)
	if err != nil {
		return 0, domain.Record{}, err
	}
	r.Severity = domain.Severity(severity)
	r.ActorID, r.ActorType, r.TargetResource, r.SourceIP, r.UserAgent =
		deref(actorID), deref(actorType), deref(targetResource), deref(sourceIP), deref(ua)
	r.Payload = []byte(payload)
	if r.PrevHash, err = toHash(prevHash); err != nil {
		return 0, domain.Record{}, err
	}
	if r.Hash, err = toHash(hash); err != nil {
		return 0, domain.Record{}, err
	}
	return id, r, nil
}

func toHash(b []byte) (domain.Hash, error) {
	var h domain.Hash
	if len(b) != len(h) {
		return h, fmt.Errorf("hash has %d bytes, want %d", len(b), len(h))
	}
	copy(h[:], b)
	return h, nil
}

// nullable maps an absent optional field ("") to SQL NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
