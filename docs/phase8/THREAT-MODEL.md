# Optional SOC boundary review

The accepted [flagship threat model](../phase7/THREAT-MODEL.md) remains applicable. This
adds a synthetic local backend module, not a live security operations platform.

| Threat | Enforcement and validation |
| --- | --- |
| Real credentials, personal identities or arbitrary payloads supplied as events | Strict two-format schemas, fixed synthetic sources, prefixed lowercase IDs, no free-form event messages; malformed/disclosure tests |
| Duplicate or conflicting event/HTTP replay | Deterministic event IDs plus unique database identities; canonical semantic request digest; locked dataset acceptance; multiprocess conflict tests |
| Late events rewriting previous conclusions | Immutable run event sets, protected event bytes/identities and evidence; separate run occurrences and stable tracking IDs |
| False causal inference | Only two documented rules; exact actor/session linkage for IAM; incomplete evidence explicit; matched sequence does not prove compromise |
| Stale worker completion or audit | Shared token/generation/expiry predicate, DB-time locks, independent heartbeat, post-insert fence and same-transaction publication; killed-process and connection-termination tests |
| Forged evidence or correlation output | Server-side recomputation, same-dataset events and canonical hashes; timeline verification; malformed-result rejection |
| Analyst overwrite or history removal | expected_revision plus row lock; atomic state/revision/audit; DB immutable-history triggers; independent reviewer processes produce one success and one 409 |
| Resource exhaustion | Existing request boundary; batch/history/context/outcome limits; dataset/run/revision quotas; container CPU/memory/PID/tmp limits; bounded retries |
| Browser/API exposure or operational secret logging | Existing authenticated local boundary and sanitized errors; no new frontend; no token in CLI options/output; synthetic disclosure tests and final artifact inspection |
| Optional schema poisoning flagship readiness or migration | Separate Base/version table, schema-only autogeneration, no public FK; real downgrade/re-upgrade and absent-module subprocess tests |
| Privileged scanner/model access | SOC worker has no spool/Docker mount, launcher/provider credential or model tools; real admission stays disabled |

The trusted operator, Python implementation, database administrator and Docker Desktop
remain trusted. A shared database owner in the optional overlay can technically access
AppSec tables; this is not tenant or database-role isolation. The separate demonstration
database avoids any retained AppSec write. A compromised privileged local account remains
outside the assurance claim.

Retention intentionally preserves all referenced/replay history. Quotas can require
operator intervention. There is no automatic decommission/delete command. Notes are
sanitized heuristically, not through comprehensive DLP. Event timestamps and source labels
are assertions from an authorized synthetic producer, not cryptographically authenticated
enterprise telemetry. Backups and frozen evaluation artifacts remain private and unchanged.

No universal threat-detection, production availability, live model quality, automatic
response or enterprise SOC capability is claimed. Original A13, unsupported scanner
coverage and ungraded annotation limitations remain visible in the flagship reports.
