# Deploying on Infomaniak shared hosting

> Draft written in phase 1. It is completed and tested in phase 6.

## What the hosting must offer

- PHP 8.2 or later with `pdo_mysql` and `mbstring`
- One MariaDB (or MySQL) database
- Scheduled tasks (cron) running PHP CLI scripts
- SSH or SFTP access
- Apache with `mod_rewrite` and `mod_headers` (`.htaccess` allowed)

To confirm in the Manager: PHP version, minimum interval and maximum duration of scheduled tasks, and whether database users can have per-table rights.

## Target layout

```
~/riskstudio-app/          application root, NOT reachable from the web
    .env                   production secrets
    src/  vendor/  bin/    PHP API and collector
    db/                    migrations and seeds
~/sites/riskstudio/        web root of the site
    index.html  _app/  .htaccess   static build (web/build)
    api/index.php          2-line stub that loads ~/riskstudio-app/public/index.php
    api/.htaccess          rewrites /api/* to index.php
```

## Database users on shared hosting

The Infomaniak Manager creates database users with preset rights. If per-table `GRANT` statements are not available:

1. Create `rs_admin` with full rights: used only from SSH to run migrations.
2. Create `rs_write` with read and write rights.
3. Create `rs_read` with **read-only** rights.
4. Proposals are then inserted by the API through `rs_write`, on that single endpoint, with a server-side forced `pending` status.

The public views still protect reads: the public API code only ever queries `v_public_*`.

## Steps (to be finalised in phase 6)

1. `make build` and `composer install --no-dev --optimize-autoloader`.
2. Upload the content of `api/` and the `db/` folder to `~/riskstudio-app/`, and `web/build/` to the web root. The `api/index.php` stub in the web root sets `RS_APP_ROOT` and requires `~/riskstudio-app/public/index.php`.
3. Create `~/riskstudio-app/.env` from `api/.env.example`, with `APP_ENV=prod`.
4. From SSH: `php ~/riskstudio-app/bin/migrate.php --seed` with `RS_DB_DIR=~/riskstudio-app/db`.
5. Apply `db/grants.sql` if allowed, otherwise follow the section above.
6. Declare the collector scheduled task (see below).

## Collector scheduled task

In the Infomaniak Manager, create a scheduled task every **15 minutes** running:

```bash
php ~/riskstudio-app/bin/collect.php
```

With `RS_DB_DIR=~/riskstudio-app/db` if the `db/` folder is not next to `bin/`. Keep `COLLECTOR_TIME_BUDGET` (50 s by default) below the maximum duration the hosting allows for a scheduled task. A run that finds another run in progress exits immediately (database lock).

Each run is journaled in `collector_runs` (status, counts, errors), kept 30 days. Exit code: 0 success, 2 when a source failed, 1 on a configuration error.

Optional: request a free NVD API key and set `NVD_API_KEY`, to complete CVSS scores 8 times faster.

Before enabling the **CCB** source, check from the hosting SSH that the CCB advisory feed answers (`curl -I`), since the CCB site rejects requests from some data centres.
