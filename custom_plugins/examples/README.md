# Example custom plugins (opt-in)

These pedagogical plugins live **outside** the default auto-discovery directory
(`custom_plugins/*.rs`) so default source, release, and Docker builds neither
register them nor collect their SQL migrations.

## Include at build time

```bash
FERRUM_CUSTOM_PLUGINS=example_plugin,example_audit_plugin cargo build
```

Or copy a file into `custom_plugins/` (the production discovery directory):

```bash
cp custom_plugins/examples/example_audit_plugin.rs custom_plugins/
cargo build
```

## `example_audit_plugin` storage notes

Runtime writes use the gateway SQL configuration database via
`EnvConfig::resolve_effective_sql_backend` (`FERRUM_DB_TYPE` / `FERRUM_DB_URL` /
`FERRUM_DB_TLS_*`). MongoDB is rejected. The worker pool is created lazily in
`start_background_tasks`; construction does not open a network connection.

## Uninstall / leftover schema

Custom plugin migrations have no automatic down path. If you previously opted
the example in, applied migrations, then removed the plugin from the binary,
`example_audit_log` / `_ferrum_plugin_migrations` rows remain until an operator
drops them deliberately.
