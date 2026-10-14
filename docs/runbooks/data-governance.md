# Runbook: DSAR, retention, legal hold

## Through the gateway (privacy officer)

Enable: set `GW_GOV_MASTER_KEY` (64 hex, keep it in the secret store; rotating it breaks outstanding evidence tokens) on the gateway process and make its database
role a member of `axis_governance`. Without the key every `/governance` operation is a 503. Give a member the `privacy_officer` role (owners and admins can
only read). Then, with that member's API key:

1. `axis governance requests create --kind erase --file ids.yaml` (the file holds `identifiers: [{kind, value}]`; the command line would land in shell history). The 30-day clock starts; the response shows an opaque `subject_ref`.
2. Prove the data subject's identity out of band and have an independent tenant owner or admin attest: the tenant's proofing tooling produces `requester_token` (bound to the request id and `subject_ref`), the admin's tooling produces `admin_attestation`. `axis governance requests verify <id> --file evidence.yaml` exits 1 and leaves the request `received` if anything is wrong (same member as opener or verifier, not an admin, expired, wrong request).
3. `axis governance requests export <id> --out bundle.json` (signed; check it offline with `verifyBundle`) or `... erase <id>`. Exit 1 unless `completed`: `held` means a legal hold covers a store (release it, run erase again); `partial` / a 500 means residual data was found, nothing was shredded, fix the cause and run it again.
4. `axis governance requests list`, `... holds list --all`, `... retention get|runs`, `... residency` show state; the console `/governance` pages show the same read-only.
5. Retention: `axis governance retention run` is a dry run; `--execute` purges. Schedule it externally (NEEDS 375).

The sections below describe the loopback dev server, which remains for local use.

Run the dev surface: `AXIS_GOV_DATABASE_URL=... AXIS_GOV_TOKENS='{"tok":{"tenantId":"<uuid>","id":"officer","roles":["privacy_officer"]}}' AXIS_GOV_MASTER_KEY=<64 hex> AXIS_GOV_REGION=<region> node services/data-governance/dist/main.js`.
Ops must `GRANT axis_governance TO <login role>` (privileged: it can scrub personal-data columns of one tenant at a time).

## DSAR (30-day clock)

1. `POST /admin/v1/dsar {kind: export|erase|restrict, identifiers:[{kind,value}]}`; the due date is returned. Give every known identifier (email, user_ref, end_user_id, channel_identity "slack:U123", subject_key).
2. Verify the requester out of band; `POST .../verify {evidence}`. (The shipped verifier refuses; wire a real one.)
3. Export: `POST .../export`; hand over the bundle; confirm with `verifyBundle`. Erase: `POST .../erase`.
4. `status: held` -> a legal hold covers a store: decide with legal, release the hold, call erase again. `residual_data` error -> a store still holds data: fix the cause, call erase again; nothing was shredded.
5. Daily: `POST /admin/v1/dsar/sweep` (at-risk/breached events). Need more time: `.../extend` once, before the deadline.
6. Evidence: `GET /admin/v1/dsar/:id` (`result.verification`), the audit events, and an offline chain verification (`docs/runbooks/audit.md`).
   After a database restore from backup, erased subjects reappear: re-run erasures for requests completed after the backup (NEEDS 378).

## Retention

`GET /admin/v1/retention` shows requested vs effective days per class. Always `POST /admin/v1/retention/run {dry_run: true}` first and review matches; then `dry_run: false`.
Tenant-level periods for memory/transcripts/audit are control-plane settings; run_logs/eval_data/telemetry/billing via `PUT /admin/v1/retention/:class`. Schedule the run externally.

## Legal hold

`POST /admin/v1/holds {scope: tenant|subject|case, reason, classes?, case_ref?, groups?: [[identifiers]]}`. A hold suspends purge and erasure of matching data until
`POST /admin/v1/holds/:id/release`. Holds are listed with `GET /admin/v1/holds` (`?all=1` includes released).
