package domain

import (
	"fmt"
	"slices"
)

// Severity ranks how urgent an event is. Its numeric value is what audit_logs.severity stores.
type Severity int16

// Severities defined by the ingest contract, from least to most urgent.
const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// ParseSeverity converts the contract name (uppercase) into a Severity.
func ParseSeverity(name string) (Severity, error) {
	if i := slices.Index(severityNames[:], name); i >= 0 {
		return Severity(i), nil // #nosec G115 -- i indexes severityNames, so it is below 5.
	}
	return 0, fmt.Errorf("unknown severity %q", name)
}

// Valid reports whether s is one of the defined severities.
func (s Severity) Valid() bool { return s >= SeverityInfo && s <= SeverityCritical }

func (s Severity) String() string {
	if !s.Valid() {
		return fmt.Sprintf("Severity(%d)", int16(s))
	}
	return severityNames[s]
}

// sourceModules is the whitelist of MediNet-Core module codes (contract §1, table source_modules).
var sourceModules = []string{"IAM", "PAC", "MED", "AGT", "HCE", "PAB", "LAB", "FAR", "TRG", "FAC", "AUD", "TEL"}

// eventTypes is the event catalog of contract v1.0 (§2).
var eventTypes = []string{
	"auth.login_succeeded",
	"auth.login_failed",
	"auth.account_locked",
	"auth.logout",
	"auth.password_changed",
	"auth.token_rejected",
	"iam.user_created",
	"iam.user_disabled",
	"iam.role_changed",
	"iam.permission_changed",
	"access.denied",
	"access.idor_attempt",
	"data.sensitive_read",
	"data.record_created",
	"data.record_updated",
	"data.record_deleted",
	"data.export",
	"input.rejected",
	"file.upload_rejected",
	"business.rule_violation",
	"security.rate_limited",
	"security.config_changed",
}

var actorTypes = []string{"user", "service", "anonymous"}

// SourceModules returns a copy of the module whitelist.
func SourceModules() []string { return slices.Clone(sourceModules) }

// EventTypes returns a copy of the event catalog.
func EventTypes() []string { return slices.Clone(eventTypes) }
