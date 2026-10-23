"""Independent durable triage, scoped consent and immutable human review history.

DDL is frozen at generation time; no imports from current application metadata.
"""

# ruff: noqa: E501
import os

import sqlalchemy as sa
from alembic import op

revision = "0004_triage_review"
down_revision = "0003_scanner_handoff"
branch_labels = None
depends_on = None

UPGRADE_SQL = [
    "ALTER TABLE findings ADD CONSTRAINT uq_finding_scan_identity UNIQUE (scan_run_id,id)",
    "ALTER TABLE scan_runs ADD CONSTRAINT uq_scan_snapshot_identity UNIQUE (id,snapshot_id)",
    "ALTER TABLE source_snapshots ADD CONSTRAINT uq_snapshot_manifest_identity UNIQUE (id,manifest_digest)",
    "\nCREATE TABLE hosted_consents (\n\tid UUID NOT NULL, \n\toperation_id UUID NOT NULL, \n\tfinding_id UUID NOT NULL, \n\tscan_run_id UUID NOT NULL, \n\tsnapshot_id UUID NOT NULL, \n\tmanifest_digest VARCHAR(64) NOT NULL, \n\tconfig_digest VARCHAR(64) NOT NULL, \n\tdata_categories JSONB NOT NULL, \n\toperator VARCHAR(32) NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\trevoked_at TIMESTAMP WITH TIME ZONE, \n\tCONSTRAINT pk_hosted_consents PRIMARY KEY (id), \n\tCONSTRAINT uq_consent_operation UNIQUE (operation_id), \n\tCONSTRAINT fk_hosted_consents_scan_run_id_findings FOREIGN KEY(scan_run_id, finding_id) REFERENCES findings (scan_run_id, id), \n\tCONSTRAINT fk_hosted_consents_scan_run_id_scan_runs FOREIGN KEY(scan_run_id, snapshot_id) REFERENCES scan_runs (id, snapshot_id), \n\tCONSTRAINT fk_hosted_consents_snapshot_id_source_snapshots FOREIGN KEY(snapshot_id, manifest_digest) REFERENCES source_snapshots (id, manifest_digest), \n\tCONSTRAINT ck_hosted_consents_config_digest CHECK (config_digest ~ '^[0-9a-f]{64}$'), \n\tCONSTRAINT ck_hosted_consents_categories CHECK (jsonb_typeof(data_categories) = 'array' AND octet_length(data_categories::text) <= 256), \n\tCONSTRAINT ck_hosted_consents_operator CHECK (operator = 'local_operator')\n)\n\n",
    "\nCREATE TABLE triage_runs (\n\tid UUID NOT NULL, \n\tfinding_id UUID NOT NULL, \n\tscan_run_id UUID NOT NULL, \n\tsnapshot_id UUID NOT NULL, \n\tmanifest_digest VARCHAR(64) NOT NULL, \n\tprovider VARCHAR(32) NOT NULL, \n\tconfig_digest VARCHAR(64) NOT NULL, \n\tprompt_version VARCHAR(32) NOT NULL, \n\ttools_version VARCHAR(32) NOT NULL, \n\tpolicy_version VARCHAR(32) NOT NULL, \n\tconsent_id UUID, \n\tstatus VARCHAR(16) NOT NULL, \n\terror_code VARCHAR(64), \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tstarted_at TIMESTAMP WITH TIME ZONE, \n\tcompleted_at TIMESTAMP WITH TIME ZONE, \n\tCONSTRAINT pk_triage_runs PRIMARY KEY (id), \n\tCONSTRAINT uq_triage_finding_identity UNIQUE (id, finding_id), \n\tCONSTRAINT fk_triage_runs_scan_run_id_findings FOREIGN KEY(scan_run_id, finding_id) REFERENCES findings (scan_run_id, id), \n\tCONSTRAINT fk_triage_runs_scan_run_id_scan_runs FOREIGN KEY(scan_run_id, snapshot_id) REFERENCES scan_runs (id, snapshot_id), \n\tCONSTRAINT fk_triage_runs_snapshot_id_source_snapshots FOREIGN KEY(snapshot_id, manifest_digest) REFERENCES source_snapshots (id, manifest_digest), \n\tCONSTRAINT ck_triage_runs_provider CHECK (provider IN ('deterministic-v1','openai-v1')), \n\tCONSTRAINT ck_triage_runs_status CHECK (status IN ('queued','running','succeeded','unavailable','failed')), \n\tCONSTRAINT ck_triage_runs_config_digest CHECK (config_digest ~ '^[0-9a-f]{64}$'), \n\tCONSTRAINT ck_triage_runs_consent CHECK ((provider = 'openai-v1') = (consent_id IS NOT NULL)), \n\tCONSTRAINT fk_triage_runs_consent_id_hosted_consents FOREIGN KEY(consent_id) REFERENCES hosted_consents (id)\n)\n\n",
    "ALTER TABLE jobs ALTER COLUMN scanner_run_id DROP NOT NULL",
    "ALTER TABLE jobs ADD COLUMN triage_run_id UUID REFERENCES triage_runs(id)",
    "ALTER TABLE jobs ADD CONSTRAINT uq_job_triage UNIQUE (triage_run_id)",
    "ALTER TABLE jobs DROP CONSTRAINT ck_jobs_operation",
    "ALTER TABLE jobs ADD CONSTRAINT ck_jobs_operation CHECK ((operation = 'scan' AND scanner_run_id IS NOT NULL AND triage_run_id IS NULL) OR (operation = 'triage' AND scanner_run_id IS NULL AND triage_run_id IS NOT NULL))",
    "ALTER TABLE idempotency_requests ALTER COLUMN scan_run_id DROP NOT NULL",
    "ALTER TABLE idempotency_requests ADD COLUMN triage_run_id UUID REFERENCES triage_runs(id)",
    "ALTER TABLE idempotency_requests ADD CONSTRAINT ck_idempotency_requests_one_target CHECK ((scan_run_id IS NULL) != (triage_run_id IS NULL))",
    "\nCREATE TABLE triage_outcomes (\n\ttriage_run_id UUID NOT NULL, \n\tjob_id UUID NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tresult JSONB NOT NULL, \n\ttrace JSONB NOT NULL, \n\tusage JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tCONSTRAINT pk_triage_outcomes PRIMARY KEY (triage_run_id), \n\tCONSTRAINT fk_triage_outcomes_job_id_job_attempts FOREIGN KEY(job_id, generation) REFERENCES job_attempts (job_id, generation), \n\tCONSTRAINT ck_triage_outcomes_result CHECK (jsonb_typeof(result) = 'object' AND octet_length(result::text) <= 16384), \n\tCONSTRAINT ck_triage_outcomes_trace CHECK (jsonb_typeof(trace) = 'array' AND octet_length(trace::text) <= 4096), \n\tCONSTRAINT ck_triage_outcomes_usage CHECK (jsonb_typeof(usage) = 'object' AND octet_length(usage::text) <= 2048), \n\tCONSTRAINT fk_triage_outcomes_triage_run_id_triage_runs FOREIGN KEY(triage_run_id) REFERENCES triage_runs (id), \n\tCONSTRAINT fk_triage_outcomes_job_id_jobs FOREIGN KEY(job_id) REFERENCES jobs (id)\n)\n\n",
    "\nCREATE TABLE triage_provider_calls (\n\tid UUID NOT NULL, \n\ttriage_run_id UUID NOT NULL, \n\tjob_id UUID NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tsequence INTEGER NOT NULL, \n\tconsent_id UUID NOT NULL, \n\treserved_micro_usd INTEGER NOT NULL, \n\treserved_tokens INTEGER NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tCONSTRAINT pk_triage_provider_calls PRIMARY KEY (id), \n\tCONSTRAINT fk_triage_provider_calls_job_id_job_attempts FOREIGN KEY(job_id, generation) REFERENCES job_attempts (job_id, generation), \n\tCONSTRAINT uq_triage_provider_sequence UNIQUE (job_id, generation, sequence), \n\tCONSTRAINT ck_triage_provider_calls_bounds CHECK (sequence BETWEEN 1 AND 10 AND reserved_micro_usd BETWEEN 0 AND 50000), \n\tCONSTRAINT fk_triage_provider_calls_triage_run_id_triage_runs FOREIGN KEY(triage_run_id) REFERENCES triage_runs (id), \n\tCONSTRAINT fk_triage_provider_calls_job_id_jobs FOREIGN KEY(job_id) REFERENCES jobs (id), \n\tCONSTRAINT fk_triage_provider_calls_consent_id_hosted_consents FOREIGN KEY(consent_id) REFERENCES hosted_consents (id)\n)\n\n",
    "\nCREATE TABLE reviews (\n\tfinding_id UUID NOT NULL, \n\trevision INTEGER NOT NULL, \n\tdisposition VARCHAR(32) NOT NULL, \n\tnote VARCHAR(2000) NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tCONSTRAINT pk_reviews PRIMARY KEY (finding_id), \n\tCONSTRAINT ck_reviews_revision CHECK (revision > 0), \n\tCONSTRAINT ck_reviews_disposition CHECK (disposition IN ('confirmed','false_positive','investigate','accepted_risk','remediation_planned')), \n\tCONSTRAINT ck_reviews_note CHECK (char_length(note) <= 2000), \n\tCONSTRAINT fk_reviews_finding_id_findings FOREIGN KEY(finding_id) REFERENCES findings (id)\n)\n\n",
    "\nCREATE TABLE review_revisions (\n\tid UUID NOT NULL, \n\tfinding_id UUID NOT NULL, \n\trevision INTEGER NOT NULL, \n\tdisposition VARCHAR(32) NOT NULL, \n\tnote VARCHAR(2000) NOT NULL, \n\treviewer VARCHAR(32) NOT NULL, \n\ttriage_run_id UUID, \n\tfeedback VARCHAR(16), \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tCONSTRAINT pk_review_revisions PRIMARY KEY (id), \n\tCONSTRAINT uq_review_revision UNIQUE (finding_id, revision), \n\tCONSTRAINT fk_review_revisions_triage_run_id_triage_runs FOREIGN KEY(triage_run_id, finding_id) REFERENCES triage_runs (id, finding_id), \n\tCONSTRAINT ck_review_revisions_revision CHECK (revision > 0), \n\tCONSTRAINT ck_review_revisions_disposition CHECK (disposition IN ('confirmed','false_positive','investigate','accepted_risk','remediation_planned')), \n\tCONSTRAINT ck_review_revisions_content CHECK (char_length(note) <= 2000 AND reviewer = 'local_operator'), \n\tCONSTRAINT ck_review_revisions_feedback CHECK (feedback IS NULL OR feedback IN ('agree','disagree','uncertain')), \n\tCONSTRAINT fk_review_revisions_finding_id_findings FOREIGN KEY(finding_id) REFERENCES findings (id)\n)\n\n",
    "ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_event_allowlist",
    "ALTER TABLE audit_events ADD CONSTRAINT ck_audit_events_event_allowlist CHECK ((event_type = 'project.created' AND object_type = 'project') OR (event_type = 'snapshot.registered' AND object_type = 'source_snapshot') OR (event_type = 'scan.accepted' AND object_type = 'scan') OR (event_type IN ('triage.accepted','triage.send_reserved') AND object_type = 'triage') OR (event_type IN ('consent.created','consent.revoked') AND object_type = 'consent') OR (event_type = 'review.updated' AND object_type = 'review') OR (event_type IN ('job.claimed','job.succeeded','job.retry_pending','job.failed','job.expired') AND object_type = 'job'))",
    "ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_actor_allowlist",
    "ALTER TABLE audit_events ADD CONSTRAINT ck_audit_events_actor_allowlist CHECK ((actor = 'local_operator' AND component = 'api' AND event_type NOT LIKE 'job.%%' AND event_type != 'triage.send_reserved') OR (actor = 'worker' AND component = 'worker' AND (event_type LIKE 'job.%%' OR event_type = 'triage.send_reserved')))",
    "CREATE FUNCTION reject_review_revision_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Review history is immutable'; END; $$",
    "CREATE TRIGGER review_history_immutable BEFORE UPDATE OR DELETE ON review_revisions FOR EACH ROW EXECUTE FUNCTION reject_review_revision_mutation()",
]

DOWNGRADE_SQL = [
    "DROP TABLE review_revisions",
    "DROP TABLE reviews",
    "DROP TABLE triage_provider_calls",
    "DROP TABLE triage_outcomes",
    "DELETE FROM idempotency_requests WHERE triage_run_id IS NOT NULL",
    "DELETE FROM job_attempts WHERE job_id IN (SELECT id FROM jobs WHERE operation = 'triage')",
    "DELETE FROM jobs WHERE operation = 'triage'",
    "ALTER TABLE idempotency_requests DROP CONSTRAINT ck_idempotency_requests_one_target",
    "ALTER TABLE idempotency_requests DROP COLUMN triage_run_id",
    "ALTER TABLE idempotency_requests ALTER COLUMN scan_run_id SET NOT NULL",
    "ALTER TABLE jobs DROP CONSTRAINT ck_jobs_operation",
    "ALTER TABLE jobs DROP COLUMN triage_run_id",
    "ALTER TABLE jobs ALTER COLUMN scanner_run_id SET NOT NULL",
    "ALTER TABLE jobs ADD CONSTRAINT ck_jobs_operation CHECK (operation = 'scan')",
    "DROP TABLE triage_runs",
    "DROP TABLE hosted_consents",
    "ALTER TABLE findings DROP CONSTRAINT uq_finding_scan_identity",
    "ALTER TABLE scan_runs DROP CONSTRAINT uq_scan_snapshot_identity",
    "ALTER TABLE source_snapshots DROP CONSTRAINT uq_snapshot_manifest_identity",
    "DROP FUNCTION reject_review_revision_mutation()",
    "DELETE FROM audit_events WHERE event_type IN ('triage.accepted','triage.send_reserved','consent.created','consent.revoked','review.updated')",
    "ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_event_allowlist",
    "ALTER TABLE audit_events ADD CONSTRAINT ck_audit_events_event_allowlist CHECK ((event_type='project.created' AND object_type='project') OR (event_type='snapshot.registered' AND object_type='source_snapshot') OR (event_type='scan.accepted' AND object_type='scan') OR (event_type IN ('job.claimed','job.succeeded','job.retry_pending','job.failed','job.expired') AND object_type='job'))",
    "ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_actor_allowlist",
    "ALTER TABLE audit_events ADD CONSTRAINT ck_audit_events_actor_allowlist CHECK ((actor='local_operator' AND component='api' AND event_type NOT LIKE 'job.%') OR (actor='worker' AND component='worker' AND event_type LIKE 'job.%'))",
]


def upgrade():
    for statement in UPGRADE_SQL:
        op.execute(sa.text(statement))


def downgrade():
    if os.environ.get("ASP_DISPOSABLE_TEST_DB") != "asp_phase1_test" or op.get_bind().execute(
        sa.text("SELECT current_database(), current_user")
    ).one() != ("asp_phase1_test", "asp_test"):
        raise RuntimeError("Destructive reversal requires the disposable test identity")
    for statement in DOWNGRADE_SQL:
        op.execute(sa.text(statement))
