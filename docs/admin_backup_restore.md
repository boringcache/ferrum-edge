# Admin API: Backup & Restore

The Ferrum Edge Admin API provides dedicated endpoints for full configuration backup and restore, enabling disaster recovery, environment migration, and configuration snapshots.

## Overview

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/backup` | GET | Export complete gateway config as JSON |
| `/restore?confirm=true` | POST | Replace all config from a backup payload |

Both endpoints require JWT authentication. The restore endpoint is blocked in read-only mode.

## Backup — `GET /backup`

Returns the entire gateway configuration as a single JSON document. The output format is directly compatible with both `POST /restore` (full replacement) and `POST /batch` (additive import).

### Key Behaviors

- **Unredacted credentials**: Unlike `GET /consumers` (which redacts `basicauth.password_hash`, `hmac_auth.secret`, and `jwt.secret`), the backup endpoint returns raw credential values. This is necessary for faithful restoration.
- **Database-first with cached fallback**: Reads from the database when available. If the database is unreachable, falls back to the in-memory cached config and sets the `X-Data-Source: cached` response header.
- **Content-Disposition header**: Includes `attachment; filename="ferrum-backup.json"` for browser-friendly downloads.
- **Resource filtering**: Use `?resources=proxies,consumers` to export only specific resource types. Valid values: `proxies`, `consumers`, `plugin_configs`, `upstreams`. Omit the parameter to export everything.

### Example

```bash
# Full backup
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/backup | jq . > ferrum-backup.json

# Partial backup (proxies and upstreams only)
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/backup?resources=proxies,upstreams" | jq . > proxies-backup.json

# Check what's in the backup
cat ferrum-backup.json | jq '.counts'
# {
#   "proxies": 42,
#   "consumers": 150,
#   "plugin_configs": 85,
#   "upstreams": 12
# }
```

### Response Format

```json
{
  "version": "1",
  "exported_at": "2025-03-26T10:30:00Z",
  "source": "database",
  "counts": {
    "proxies": 42,
    "consumers": 150,
    "plugin_configs": 85,
    "upstreams": 12
  },
  "proxies": [ ... ],
  "consumers": [ ... ],
  "plugin_configs": [ ... ],
  "upstreams": [ ... ]
}
```

## Restore — `POST /restore?confirm=true`

Replaces the entire gateway configuration with the provided backup payload. This is a **destructive operation**, but the payload is validated before any data is deleted:

1. **Validates** the payload for internal consistency (config version compatibility, resource ID uniqueness, consumer identity/credential uniqueness, regex listen_path compilation and length limits, listen_path+hosts uniqueness, stream proxy configuration including response_body_mode, upstream references). If validation fails, the request returns `400` with detailed errors and **existing config is NOT deleted**.
2. **Snapshots** the current namespace configuration for recovery (fail-safe — see below)
3. **Deletes** all existing proxies, consumers, plugin configs, upstreams, and junction table entries
4. **Imports** the provided resources in dependency order
5. **Rolls back** to the snapshot if the delete or any import persistence step fails

### Recovery snapshot is authoritative and fail-safe

The recovery snapshot in step 2 is captured with a **non-validating raw load from the primary** (`load_namespace_snapshot`), *not* the validating `load_full_config`. That distinction matters two ways:

- **Invalid-but-present config still snapshots.** An already-invalid namespace (dangling references, conflicting listen_paths, invalid regex) — precisely what an operator runs restore to *repair* — loads its raw rows without the fatal validation pipeline, so the snapshot succeeds and rollback stays available throughout the repair. A restore that imports cleanly succeeds and repairs the namespace; if a later step fails, rollback reapplies the (still invalid) prior config.
- **A genuine database failure aborts the restore.** If the snapshot cannot be taken at all — a real connectivity/timeout error rather than invalid content — the restore **aborts with `503` before deleting anything** and leaves the prior config untouched. This is fail-safe: a config that is valid but merely transiently unreachable is never wiped when we cannot capture a rollback point. Retry once the database is reachable.

Both the config resources and the `api_specs` identities are read from the **primary**, never a lagging read replica, so the recovery report is authoritative.

### API specs are not restored by rollback

`api_specs` are admin-only metadata that live **outside** `GatewayConfig`, so the delete phase removes them but the config rollback cannot bring them back. When a failed restore rolls back a namespace that carried specs, the `500` response reports `api_specs_not_restored` (the **authoritative total**), `api_specs_lost` (the exact `id` + `proxy_id` of each dropped spec, capped at 500 entries), `api_specs_lost_truncated` (`true` when more specs were removed than are listed — use `GET /api-specs` to enumerate the rest), and `api_specs_note` (guidance).

Recovery is not a bare re-submit: rollback reapplies the spec-owned proxy/upstream/plugins as **hand-managed** resources (their `api_spec_id` is cleared), so a plain `POST /api-specs` for the same spec collides on route/name/id uniqueness. To reattach a spec, first delete the restored proxy (and its upstream/plugins) listed under `api_specs_lost`, then re-submit the original spec document via `POST /api-specs`. Successful restores are unaffected — they replace the namespace, including specs, from scratch.

### Safety Guard

The `?confirm=true` query parameter is required. Without it, the endpoint returns `400 Bad Request` with a descriptive error message. This prevents accidental invocation.

### Request Format

Accepts the same JSON format produced by `GET /backup`. All resource arrays are optional — omitted types are treated as empty (meaning existing resources of that type will be deleted but not replaced).

```json
{
  "proxies": [ ... ],
  "consumers": [ ... ],
  "plugin_configs": [ ... ],
  "upstreams": [ ... ]
}
```

The `exported_at`, `source`, and `counts` metadata fields from a backup are silently ignored if present, so you can pass a backup response directly as the restore payload. The `version` field, if present, is validated against the current config version — a mismatch returns `400 Bad Request`.

### Body Size Limit

The restore endpoint accepts up to **100 MiB** request bodies by default (vs. 1 MiB for other endpoints), which comfortably covers 30K proxies + 30K consumers + 90K plugins (~80 MB). Configurable via the `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` environment variable:

```bash
# Reduce to 50 MiB for constrained environments
FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB=50

# Increase to 200 MiB for extremely large deployments
FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB=200
```

### Size Guidance

| Deployment | Resources | Approx backup size |
|---|---|---|
| Small | ~100 proxies, ~50 consumers | 100-200 KB |
| Medium | ~1,000 proxies, ~500 consumers | 1-2 MB |
| Large | ~5,000 proxies, ~3,000 consumers | 5-10 MB |
| Very large | 10,000+ proxies, 5,000+ consumers | 15+ MB |
| Enterprise | 30,000 proxies, 30,000 consumers, 90,000 plugins | ~80 MB |

For deployments exceeding the body limit, use partial backups via `?resources=` and restore with `POST /batch` (additive).

### Memory and Performance

**Backup** serializes directly from in-memory config structs to the output buffer — no intermediate `serde_json::Value` copy. Peak memory overhead is roughly equal to the output JSON size.

**Restore** deserializes the request body directly into typed structs — again skipping the `Value` intermediate. Peak memory is body bytes + parsed structs.

**Database inserts** are chunked into 1,000-record transactions to keep WAL/redo log size bounded and avoid prolonged lock holds. A 90,000-plugin restore runs as 90 separate transactions rather than one massive transaction.

### Example: Backup & Restore Workflow

```bash
TOKEN="your-jwt-token"
SOURCE="http://source-gateway:9000"
TARGET="http://target-gateway:9000"

# 1. Backup the source gateway
curl -s -H "Authorization: Bearer $TOKEN" \
  "$SOURCE/backup" > backup.json

echo "Backed up $(cat backup.json | jq '.counts')"

# 2. Restore to the target gateway
curl -s -X POST "$TARGET/restore?confirm=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @backup.json | jq .

# Response:
# {
#   "restored": {
#     "proxies": 42,
#     "consumers": 150,
#     "plugin_configs": 85,
#     "upstreams": 12
#   }
# }
```

### Error Handling

If the delete or any resource type fails during import, the endpoint removes the partial state, reapplies the pre-restore snapshot, and returns `500 Internal Server Error`:

```json
{
  "error": "Restore failed; restore rolled back and prior config retained",
  "restore_errors": [
    "consumers: unique constraint violation on username"
  ],
  "rollback": "completed",
  "api_specs_not_restored": 2,
  "api_specs_lost": [
    { "id": "spec-1", "proxy_id": "orders-proxy" },
    { "id": "spec-2", "proxy_id": "billing-proxy" }
  ],
  "api_specs_lost_truncated": false,
  "api_specs_note": "2 API spec(s) were removed and cannot be restored by rollback. Their proxy/upstream/plugin resources were reapplied as hand-managed (api_spec_id cleared), so re-submitting a spec via POST /api-specs first requires deleting the restored proxy (and its upstream/plugins) to avoid route/name/id collisions, then re-submitting the original spec document. Affected specs are listed in api_specs_lost."
}
```

The `rollback` field reports the outcome:

- `completed` — the prior config was reapplied and retained.
- `incomplete` — reapplying the prior config failed; the response includes `rollback_errors` and instructs the operator to perform manual recovery. The rollback is best-effort because it uses the same database backend that reported the failure.
- `not_needed` — the **clear itself failed atomically** (SQL runs it in one transaction; replica-set MongoDB in a multi-document transaction). Nothing was deleted, so the prior config — including its `api_specs` — is fully intact and no compensating re-import runs. Only standalone (non-replica-set) MongoDB, whose clear deletes collections one-by-one, can leave a partial state and take the `completed`/`incomplete` path on a delete failure.

There is no `unavailable` outcome: when the prior config cannot be snapshotted for rollback, the restore **aborts before any delete** and returns `503` (not `500`) with an `error` explaining that the existing config was NOT deleted. This is the fail-safe path — the destructive delete never runs when a rollback point cannot be captured.

`api_specs_not_restored` / `api_specs_lost` / `api_specs_lost_truncated` / `api_specs_note` appear only when the namespace carried API specs, which a config rollback cannot restore (see above). The payload is still validated before the snapshot and delete phases; validation failures return `400` and leave existing config untouched.

#### Restore aborted — `503`

```json
{
  "error": "Restore aborted: the prior configuration could not be snapshotted for rollback (database unavailable). Existing config was NOT deleted; retry once the database is reachable.",
  "restore_errors": [
    "failed to snapshot prior config for rollback: pool timed out while waiting for an open connection"
  ]
}
```

## Restore vs. Batch

| Feature | `POST /restore` | `POST /batch` |
|---------|-----------------|---------------|
| Deletes existing data | Yes (full wipe) | No (additive) |
| Safety guard | Requires `?confirm=true` | None |
| Use case | Disaster recovery, environment migration | Incremental provisioning |
| Body size limit | 100 MiB (configurable) | 1 MiB |
| Response key | `restored` | `created` |

## Backup in File Mode and Data Plane Mode

In **file mode** and **data plane mode**, there is no database. The backup endpoint falls back to the in-memory cached config:

```bash
# Works in file/DP mode — returns cached config
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/backup

# Response includes: "source": "cached"
```

Restore requires a database and will return `503 Service Unavailable` in file/DP mode.

## Recommended Practices

1. **Keep external backups**: Restore takes an automatic recovery snapshot, but periodic external backups remain necessary for database-wide outages and disaster recovery.
2. **Validate backup integrity**: Check the `counts` field matches expectations before restoring.
3. **Use batch for incremental changes**: If you only need to add resources without wiping existing ones, use `POST /batch` instead.
4. **Automate periodic backups**: Schedule `GET /backup` via cron for disaster recovery snapshots.
5. **Cross-environment migration**: Use backup/restore to promote configuration from staging to production.
