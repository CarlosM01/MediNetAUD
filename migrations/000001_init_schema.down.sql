-- Development only: dropping audit_logs destroys the audit trail.
DROP TABLE audit_logs;
DROP FUNCTION audit_logs_reject_mutation();
DROP TABLE api_clients;
DROP TABLE source_modules;
