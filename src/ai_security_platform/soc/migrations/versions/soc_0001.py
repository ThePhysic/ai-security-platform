# ruff: noqa: E501
"""Independent SOC schema. Frozen DDL; no AppSec migration dependency."""

from alembic import op

revision = "soc_0001"
down_revision = None
branch_labels = None
depends_on = None

DDL = (
    "\nCREATE TABLE soc.audit_events (\n\tid UUID NOT NULL, \n\tevent VARCHAR(32) NOT NULL, \n\tobject_id UUID NOT NULL, \n\tgeneration INTEGER, \n\trequest_id VARCHAR(64) NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tPRIMARY KEY (id), \n\tCHECK (event IN ('dataset.created','events.accepted','job.claimed','job.succeeded','job.retry_pending','job.expired','job.failed','review.created')), \n\tCHECK (request_id ~ '^[A-Za-z0-9_-]{1,64}$')\n)\n\n",
    "\nCREATE TABLE soc.datasets (\n\tid UUID NOT NULL, \n\tlabel VARCHAR(32) NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tPRIMARY KEY (id), \n\tCHECK (label IN ('synthetic-demo','synthetic-test'))\n)\n\n",
    "\nCREATE TABLE soc.correlation_runs (\n\tid UUID NOT NULL, \n\tdataset_id UUID NOT NULL, \n\tidempotency_key VARCHAR(128) NOT NULL, \n\trequest_digest VARCHAR(64) NOT NULL, \n\trules_digest VARCHAR(64) NOT NULL, \n\tstatus VARCHAR(16) NOT NULL, \n\tevent_ids JSONB NOT NULL, \n\tacceptance JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tcompleted_at TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY (id), \n\tUNIQUE (dataset_id, idempotency_key), \n\tUNIQUE (dataset_id, id), \n\tCHECK (status IN ('queued','running','succeeded','failed')), \n\tCHECK (jsonb_array_length(event_ids) BETWEEN 1 AND 1000), \n\tCHECK (idempotency_key ~ '^[A-Za-z0-9_.-]{1,128}$'), \n\tCHECK (request_digest ~ '^[0-9a-f]{64}$' AND rules_digest ~ '^[0-9a-f]{64}$'), \n\tFOREIGN KEY(dataset_id) REFERENCES soc.datasets (id)\n)\n\n",
    "\nCREATE TABLE soc.security_events (\n\tid UUID NOT NULL, \n\tdataset_id UUID NOT NULL, \n\tsource_id VARCHAR(32) NOT NULL, \n\texternal_id VARCHAR(24) NOT NULL, \n\toccurred_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tingested_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tpayload_digest VARCHAR(64) NOT NULL, \n\tcanonical JSONB NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (dataset_id, source_id, external_id), \n\tUNIQUE (dataset_id, id), \n\tCHECK (source_id IN ('synthetic-idp','synthetic-cloud')), \n\tCHECK (payload_digest ~ '^[0-9a-f]{64}$'), \n\tCHECK (octet_length(canonical::text) <= 2048), \n\tFOREIGN KEY(dataset_id) REFERENCES soc.datasets (id)\n)\n\n",
    "CREATE INDEX ix_soc_events_history ON soc.security_events (dataset_id, ingested_at DESC, id DESC)",
    "CREATE INDEX ix_soc_events_timeline ON soc.security_events (dataset_id, occurred_at, id)",
    "\nCREATE TABLE soc.jobs (\n\tid UUID NOT NULL, \n\trun_id UUID NOT NULL, \n\toperation VARCHAR(16) NOT NULL, \n\tstate VARCHAR(32) NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tattempts INTEGER NOT NULL, \n\tmax_attempts INTEGER NOT NULL, \n\tnext_attempt_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tlease_token UUID, \n\tlease_expires_at TIMESTAMP WITH TIME ZONE, \n\theartbeat_at TIMESTAMP WITH TIME ZONE, \n\tattempt_deadline TIMESTAMP WITH TIME ZONE, \n\tworker_id UUID, \n\trequest_id VARCHAR(64) NOT NULL, \n\terror_code VARCHAR(32), \n\tPRIMARY KEY (id), \n\tUNIQUE (run_id), \n\tCHECK (operation = 'soc'), \n\tCHECK (state IN ('queued','running','retry_pending','succeeded','terminal_failed')), \n\tCHECK (attempts = generation AND attempts >= 0 AND attempts <= max_attempts AND max_attempts BETWEEN 1 AND 5), \n\tCHECK ((state = 'running' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND heartbeat_at IS NOT NULL AND attempt_deadline IS NOT NULL) OR (state != 'running' AND lease_token IS NULL AND lease_expires_at IS NULL AND heartbeat_at IS NULL AND attempt_deadline IS NULL)), \n\tCHECK (request_id ~ '^[A-Za-z0-9_-]{1,64}$'), \n\tFOREIGN KEY(run_id) REFERENCES soc.correlation_runs (id)\n)\n\n",
    "CREATE INDEX ix_soc_jobs_due ON soc.jobs (next_attempt_at, id) WHERE state IN ('queued','retry_pending')",
    "CREATE INDEX ix_soc_jobs_expired ON soc.jobs (lease_expires_at, id) WHERE state = 'running'",
    "\nCREATE TABLE soc.job_attempts (\n\tid UUID NOT NULL, \n\tjob_id UUID NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\toutcome VARCHAR(32) NOT NULL, \n\tstarted_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tcompleted_at TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY (id), \n\tUNIQUE (job_id, generation), \n\tCHECK (generation > 0), \n\tCHECK (outcome IN ('running','succeeded','retry_pending','expired','failed')), \n\tCHECK ((outcome = 'running' AND completed_at IS NULL) OR (outcome != 'running' AND completed_at IS NOT NULL)), \n\tFOREIGN KEY(job_id) REFERENCES soc.jobs (id)\n)\n\n",
    "\nCREATE TABLE soc.investigations (\n\tid UUID NOT NULL, \n\tdataset_id UUID NOT NULL, \n\trun_id UUID NOT NULL, \n\tjob_id UUID NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\ttracking_id VARCHAR(64) NOT NULL, \n\trule_id VARCHAR(32) NOT NULL, \n\tevidence_state VARCHAR(16) NOT NULL, \n\tevidence JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\trevision INTEGER NOT NULL, \n\tdisposition VARCHAR(32), \n\tPRIMARY KEY (id), \n\tUNIQUE (run_id, tracking_id), \n\tFOREIGN KEY(job_id, generation) REFERENCES soc.job_attempts (job_id, generation), \n\tFOREIGN KEY(dataset_id, run_id) REFERENCES soc.correlation_runs (dataset_id, id), \n\tCHECK (rule_id IN ('auth-burst-success-v1','session-admin-grant-v1')), \n\tCHECK (evidence_state IN ('matched','incomplete')), \n\tCHECK (jsonb_array_length(evidence) BETWEEN 1 AND 21)\n)\n\n",
    "CREATE INDEX ix_soc_investigations_history ON soc.investigations (dataset_id, created_at DESC, id DESC)",
    "\nCREATE TABLE soc.analyst_feedback (\n\tid UUID NOT NULL, \n\tinvestigation_id UUID NOT NULL, \n\trevision INTEGER NOT NULL, \n\tdisposition VARCHAR(32) NOT NULL, \n\tnote VARCHAR(1000) NOT NULL, \n\tfeedback VARCHAR(32), \n\tcreated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (investigation_id, revision), \n\tCHECK (revision > 0 AND octet_length(note) <= 4000), \n\tCHECK (disposition IN ('confirmed','false_positive','investigate','accepted_risk')), \n\tCHECK (feedback IS NULL OR feedback IN ('useful','incorrect','insufficient_evidence')), \n\tFOREIGN KEY(investigation_id) REFERENCES soc.investigations (id)\n)\n\n",
    "CREATE FUNCTION soc.deny_history_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable_soc_history'; END $$",
    "CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON soc.security_events FOR EACH ROW EXECUTE FUNCTION soc.deny_history_mutation()",
    "CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON soc.analyst_feedback FOR EACH ROW EXECUTE FUNCTION soc.deny_history_mutation()",
    "CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON soc.audit_events FOR EACH ROW EXECUTE FUNCTION soc.deny_history_mutation()",
    "CREATE FUNCTION soc.protect_run_input() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (NEW.dataset_id,NEW.idempotency_key,NEW.request_digest,NEW.rules_digest,NEW.event_ids,NEW.acceptance,NEW.created_at) IS DISTINCT FROM (OLD.dataset_id,OLD.idempotency_key,OLD.request_digest,OLD.rules_digest,OLD.event_ids,OLD.acceptance,OLD.created_at) THEN RAISE EXCEPTION 'immutable_soc_input'; END IF; RETURN NEW; END $$",
    "CREATE TRIGGER immutable_input BEFORE UPDATE ON soc.correlation_runs FOR EACH ROW EXECUTE FUNCTION soc.protect_run_input()",
    "CREATE FUNCTION soc.protect_investigation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (NEW.id,NEW.dataset_id,NEW.run_id,NEW.job_id,NEW.generation,NEW.tracking_id,NEW.rule_id,NEW.evidence_state,NEW.evidence,NEW.created_at) IS DISTINCT FROM (OLD.id,OLD.dataset_id,OLD.run_id,OLD.job_id,OLD.generation,OLD.tracking_id,OLD.rule_id,OLD.evidence_state,OLD.evidence,OLD.created_at) THEN RAISE EXCEPTION 'immutable_soc_evidence'; END IF; RETURN NEW; END $$",
    "CREATE TRIGGER immutable_evidence BEFORE UPDATE ON soc.investigations FOR EACH ROW EXECUTE FUNCTION soc.protect_investigation()",
)


def upgrade() -> None:
    for statement in DDL:
        op.execute(statement)


def downgrade() -> None:
    op.drop_table("analyst_feedback", schema="soc")
    op.drop_table("investigations", schema="soc")
    op.drop_table("job_attempts", schema="soc")
    op.drop_table("jobs", schema="soc")
    op.drop_table("security_events", schema="soc")
    op.drop_table("correlation_runs", schema="soc")
    op.drop_table("datasets", schema="soc")
    op.drop_table("audit_events", schema="soc")
    op.execute("DROP FUNCTION soc.protect_investigation()")
    op.execute("DROP FUNCTION soc.protect_run_input()")
    op.execute("DROP FUNCTION soc.deny_history_mutation()")
