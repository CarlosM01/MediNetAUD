package application

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

type fakeQueue struct {
	got [][]domain.Record
	err error
}

func (q *fakeQueue) Enqueue(r []domain.Record) error {
	if q.err != nil {
		return q.err
	}
	q.got = append(q.got, r)
	return nil
}

var (
	testNow    = time.Date(2026, 10, 25, 14, 10, 0, 123456789, time.UTC)
	testClient = ports.Client{ID: "lab-service", Module: "LAB"}
)

func newTestIngest(q ports.Queue) *Ingest {
	s := NewIngest(q)
	s.now = func() time.Time { return testNow }
	return s
}

func input(i int) domain.EventInput {
	return domain.EventInput{
		EventID:      fmt.Sprintf("00000000-0000-4000-8000-%012d", i),
		SourceModule: "LAB",
		EventType:    "data.sensitive_read",
		Severity:     "INFO",
		OccurredAt:   "2026-10-25T14:03:11Z",
	}
}

func TestSubmitEnqueuesRecordsInOrder(t *testing.T) {
	q := &fakeQueue{}
	if err := newTestIngest(q).Submit(testClient, []domain.EventInput{input(1), input(2)}, true); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(q.got) != 1 || len(q.got[0]) != 2 {
		t.Fatalf("enqueued %v, want one call with two records", q.got)
	}
	for i, r := range q.got[0] {
		if r.EventID != input(i+1).EventID {
			t.Errorf("record %d is %s: order lost", i, r.EventID)
		}
		if r.ClientID != "lab-service" {
			t.Errorf("ClientID = %q, want the authenticated client", r.ClientID)
		}
		if !r.ReceivedAt.Equal(testNow.Truncate(time.Microsecond)) {
			t.Errorf("ReceivedAt = %v, want the AUD clock truncated to microseconds", r.ReceivedAt)
		}
	}
}

func TestSubmitRejectsTheWholeBatchWhenOneEventIsInvalid(t *testing.T) {
	q := &fakeQueue{}
	bad := input(2)
	bad.Severity = "SEVERE"
	err := newTestIngest(q).Submit(testClient, []domain.EventInput{input(1), bad}, true)

	var verr *domain.ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("err = %v, want *domain.ValidationError", err)
	}
	if len(verr.Fields) != 1 || verr.Fields[0].Field != "events[1].severity" {
		t.Fatalf("fields = %+v, want events[1].severity", verr.Fields)
	}
	if len(q.got) != 0 {
		t.Fatal("an invalid batch reached the queue")
	}
}

func TestSubmitSingleEventKeepsPlainFieldNames(t *testing.T) {
	bad := input(1)
	bad.EventType = "nope"
	err := newTestIngest(&fakeQueue{}).Submit(testClient, []domain.EventInput{bad}, false)
	var verr *domain.ValidationError
	if !errors.As(err, &verr) || verr.Fields[0].Field != "event_type" {
		t.Fatalf("err = %v, want a field error on event_type", err)
	}
}

func TestSubmitRejectsOtherModules(t *testing.T) {
	q := &fakeQueue{}
	other := input(2)
	other.SourceModule = "FAR"
	err := newTestIngest(q).Submit(testClient, []domain.EventInput{input(1), other}, true)
	if !errors.Is(err, ErrModuleMismatch) {
		t.Fatalf("err = %v, want ErrModuleMismatch", err)
	}
	if len(q.got) != 0 {
		t.Fatal("a forbidden batch reached the queue")
	}
}

func TestSubmitReturnsQueueErrors(t *testing.T) {
	for _, want := range []error{ports.ErrQueueFull, ports.ErrQueueClosed} {
		err := newTestIngest(&fakeQueue{err: want}).Submit(testClient, []domain.EventInput{input(1)}, false)
		if !errors.Is(err, want) {
			t.Errorf("err = %v, want %v", err, want)
		}
	}
}
