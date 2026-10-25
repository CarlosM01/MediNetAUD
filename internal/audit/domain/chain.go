package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"time"
)

// Hash is a SHA-256 digest that links a record to the previous one.
type Hash [sha256.Size]byte

// GenesisHash is the prev_hash of the first record: 32 zero bytes.
var GenesisHash Hash

// Record is an event as stored in the append-only chain.
type Record struct {
	Event
	ClientID   string
	ReceivedAt time.Time
	PrevHash   Hash
	Hash       Hash
}

// Seal links r to prev and computes its hash.
func (r *Record) Seal(prev Hash) {
	r.PrevHash = prev
	r.Hash = ComputeHash(prev, *r)
}

// ComputeHash returns SHA256(prev || canonical(r)). It ignores r.PrevHash and r.Hash.
func ComputeHash(prev Hash, r Record) Hash {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(canonical(r))
	var out Hash
	h.Sum(out[:0])
	return out
}

// canonicalVersion prefixes the serialization so a future format can coexist with this one.
const canonicalVersion = "aud.v1"

// canonicalTime matches what timestamptz stores: UTC with microsecond precision.
const canonicalTime = "2006-01-02T15:04:05.000000Z"

// canonical serializes the record fields in a fixed order. Each field is written as a
// presence byte (0 absent, 1 present) followed by its length (uint32, big endian) and bytes,
// so no two different records produce the same serialization.
//
// This is a persisted format: changing it breaks the verification of existing records.
func canonical(r Record) []byte {
	fields := []string{
		r.EventID,
		r.ClientID,
		r.SourceModule,
		r.EventType,
		strconv.Itoa(int(r.Severity)),
		r.ActorID,
		r.ActorType,
		r.TargetResource,
		r.SourceIP,
		r.UserAgent,
		formatCanonicalTime(r.OccurredAt),
		formatCanonicalTime(r.ReceivedAt),
		string(r.Payload),
	}

	size := len(canonicalVersion)
	for _, f := range fields {
		size += 5 + len(f)
	}
	buf := make([]byte, 0, size)
	buf = append(buf, canonicalVersion...)
	for _, f := range fields {
		if f == "" {
			buf = append(buf, 0)
			continue
		}
		buf = append(buf, 1)
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(f)))
		buf = append(buf, f...)
	}
	return buf
}

func formatCanonicalTime(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format(canonicalTime)
}
