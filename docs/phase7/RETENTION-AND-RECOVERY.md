# Retention and matched recovery contract

Maintenance is an explicit trusted-host operation. There is no HTTP maintenance endpoint,
background garbage collector, archive upload, arbitrary Docker command proxy or DB row purge.
Run commands from the workspace root with the established frozen Python environment.

## Source retention

```powershell
uv run --frozen python -m scripts.maintenance retention
uv run --frozen python -m scripts.maintenance artifacts
```

The first command is a dry run. It reports spool bytes/counts/limits and eligibility
reasons. It holds the publisher lock and database SHARE locks while inspecting references.
Every `source_snapshots` row protects its spool key, including expired or unavailable
metadata. Foreign keys preserve the scan -> scanner/job/finding -> triage/review chain.
Unverified legacy metadata is not invented source evidence.

Only an unregistered publication with a valid canonical manifest and acquisition time at
least seven days old is eligible. That grace covers the maximum configurable admission
window. Missing required source, unknown entries, digest mismatch, uncertain references,
links, reparse points, hardlinks, unsafe paths or lock failure stop the operation.

After reviewing the plan, an explicit `retention --apply` rechecks under the same locks
and removes only those eligible direct children. The entire bounded tree is validated
before deletion. NTFS deletion uses pinned ancestors/child handles; POSIX uses no-follow
descriptors and relative unlink/rmdir. No registered snapshot or DB row is deleted.

The existing `asp snapshot-cleanup-staging` removes only validated abandoned unpublished
staging older than one hour, now using the same hardened deletion primitive. Production
retained source was inspected only during validation; the one reclaimed orphan belonged
to the disposable clean spool. [Actual retention proof](retention-evidence.json).

Defaults remain 32 publications / 128 MiB spool, 512 files and 16 MiB content/snapshot,
1 MiB/file plus path/directory/enumeration budgets. Full retained storage stops intake.
This phase does not delete historical DB/source relationships or satisfy a legal hard
deletion deadline. Unknown/partial data is preserved for operator investigation.

## Generated data

JSON/SARIF publication is serialized and exclusive: maximum 64 files / 64 MiB aggregate,
4 MiB/report. Existing files are never replaced. Inspection reports count/bytes/temporary
count without reading source content. Unknown artifacts or hardlink ambiguity fail closed;
exports and abandoned partial outputs are not automatically deleted. An interrupted link
publication can therefore require operator inspection before more exports are admitted.

Raw scanner output stays in bounded buffers; container root/source are read-only and
temporary storage is bounded. The fixed-label launcher reconciles its owned orphan
containers after restart. Stop that launcher before running containment probes. Preserve
scanner assets, accepted evidence, reports and DB history; no unscoped filesystem/Docker
cleanup is part of maintenance.

## Private matched backups

```powershell
uv run --frozen python -m scripts.maintenance backup |
  Set-Content -Encoding utf8 .cache/phase7-backup-receipt.json
```

The receipt contains an opaque key and manifest SHA-256, not credentials. Keep a trusted
copy separately from the bundle. Do not print or upload backup contents. Location:
`.local/backups/phase7/<key>/`; private NTFS ACL or POSIX owner-only permissions, ignored
by Git and excluded by the Docker context allowlist. Never include `.local/` or `.cache/`
in a review ZIP. Use an explicit source/docs allowlist for any separately authorized package.

For minimal interference, stop only this project's API/ordinary/triage workers and host
launcher before backup; leave its DB running. Resume with the runbook after verification.
The implementation also protects consistency with these locks:

1. Hold the same exclusive publisher lock used by source acquisition.
2. Acquire SHARE locks on all 17 application tables and Alembic in one transaction.
   Data writes are excluded while readers/pg_dump can proceed. Lock wait is bounded.
3. Validate registered source identity and capture all published snapshots, including
   unregistered publications whose registration window still matters.
4. Capture trusted policy metadata, a custom-format PostgreSQL dump and table fingerprints.
   All review revisions, audit events, jobs/attempts, provenance and consent history are
   included. Compare DB state before/after while ownership of the lock transaction remains.
5. Write the canonical integrity manifest last and verify every payload digest plus
   DB-to-spool identity before reporting success.

Caps: three bundles including incomplete attempts; 384 MiB payload/bundle; 64 MiB streamed
dump; 100,000 rows/table; bounded file counts/paths and a 90-second dump deadline. Backups
are never silently pruned. Quota exhaustion requires inspection and an explicit separate
disposal decision. No endless automatic backup accumulation or hard time-based expiry.

The manifest identifies format/schema/PostgreSQL/scanner policy and DB versions, SHA-256
payload digests, snapshot identities and restore requirements. New backup manifests also record
Python and project-metadata/lock fingerprints. Scanner images and the 1,627,238,400-byte public
vulnerability DB remain separately retained immutable dependencies. Their provenance is
included; their image archives and DB bytes are not duplicated into each private backup.
Regenerable exports and raw scanner buffers are excluded. Restore history/evidence does
not require rescanning, but a future scan requires eligible approved scanner assets.

Checksums are not signatures or encryption. A trusted DB superuser can construct unsafe
database definitions; restore accepts a trusted platform-created bundle with an independently
trusted manifest digest, never an arbitrary uploaded archive. Filesystem encryption and
off-host disaster recovery were not implemented or exercised.

## Verification and fresh disposable restore

Substitute identifiers from the private trusted receipt, never a source-controlled request:

```powershell
uv run --frozen python -m scripts.maintenance verify --key BACKUP_KEY --manifest-digest TRUSTED_SHA256
$restoreInstance = [guid]::NewGuid().ToString('N')
uv run --frozen python -m scripts.maintenance prepare-sandbox restore --instance $restoreInstance
$restoreProject = "asp-phase7-restore-$restoreInstance"
$restoreEnvironment = ".local/phase7-restore-$restoreInstance/environment.env"
docker --context desktop-linux compose --env-file $restoreEnvironment -f compose.phase7.yaml -p $restoreProject up -d --wait db
uv run --frozen python -m scripts.maintenance restore --instance $restoreInstance --key BACKUP_KEY --manifest-digest TRUSTED_SHA256
```

The exact database name/user, Compose project/service labels, absence of DB host ports
and private destination path must match. The CLI has no retained-development restore
target. Restore instances get separate generated credentials, namespace, volume and
spool. At most three restore roots are prepared; exhausted instance quota fails rather
than deleting earlier drills. Omitting `--instance` uses the initial dedicated
`asp-phase7-restore` namespace, never the development deployment.

All backup verification precedes target writes. Backup files/directories remain pinned
through restoration. A fresh empty destination is populated without replacing data;
an exactly matching existing target can be verified/resumed. Any different nonempty
target is refused. pg_restore uses `--single-transaction --exit-on-error --no-owner --no-acl`.
All table fingerprints and registered snapshots must match before API startup.

If port 18087 is occupied, stop only the identified earlier restore API or leave it
untouched and postpone API startup. Do not change Origin/Host rules or steal a port.
After successful verification, with the approved local Phase 7 image available:

```powershell
docker --context desktop-linux compose --env-file $restoreEnvironment -f compose.phase7.yaml -p $restoreProject up -d --wait --no-build api
```

`/ready` should return 200, unauthenticated data should return 401, and authenticated
queries should return restored relationships. Credentials are in that instance's ignored
configuration; do not put them in URLs, shell arguments, logs or reports.

Missing/corrupt/mismatched source is unavailable, never substituted. Existing scan
records remain successful, triage explicitly abstains with `source_unavailable`, and
source-verified export returns `409 export_evidence_invalid` until matching bytes return.

## Interruption and rollback

A complete spool followed by interrupted pre-DB work can resume. A transactional DB
restore that loses its backend rolls back schema/data and can retry against the empty
destination. A partial spool or differing target is preserved/refused; create a new
explicit instance for the next attempt. A previously restored DB that has received new
validation/application writes is not an identical replay target.

The actual drill killed a pg_restore backend at controlled DDL, verified zero application
tables after rollback, then restored successfully. No retained development database,
unrelated directory or volume was a destructive target. [Restore evidence](restore-evidence.json).

Rollback stops only the failed disposable services, preserves all volumes/spools/backups,
and keeps development running from compatible code/schema. No migration was introduced;
revision remains 0004. Prefer a forward fix or a separately verified matching restore;
do not downgrade retained data or erase failed attempts to hide an integrity problem.
