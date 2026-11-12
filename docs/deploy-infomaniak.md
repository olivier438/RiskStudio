# Deploying on Infomaniak shared hosting

Production runs on an Infomaniak web hosting: Apache + PHP + MariaDB + scheduled tasks. Nothing else. Deployments go through **GitHub Actions over SSH**: credentials stay in GitHub's encrypted secrets, never in the code or in a chat.

```
GitHub Actions  ── tests, SBOM, package ──►  rsync over SSH  ──►  Infomaniak
                                                                   …/riskstudio-app      (app/, outside the web root)
                                                                   …/<site web root>     (www/)
```

## 1. Infomaniak, once

In the Infomaniak Manager:

1. **Site**: create the site (domain or sub-domain) on the web hosting, PHP **8.3**, and enable the free **Let's Encrypt** certificate. Note the site folder (for example `/sites/riskstudio.example.org`).
2. **SSH**: in *FTP / SSH*, create an SSH account (or enable SSH on an existing one). Prefer **SFTP/SSH** to FTP: FTP sends the password in clear and cannot run the database migrations.
3. **Database**: create one MariaDB database and three users:

   | User | Rights | `.env` keys |
   |---|---|---|
   | admin user | all rights | `DB_ADMIN_*` (migrations, from SSH only) |
   | write user | read and write | `DB_WRITE_*` (back office, collector) |
   | read user | read only | `DB_READ_*` (public API) |

   The Manager gives preset rights, not per-table grants. Two settings follow from that, both safe:
   - `DB_PUBLIC_WRITES=write`: public proposals use the write user; the code never sets a proposal status, so it stays `pending` (covered by a test);
   - the public API still reads only the `v_public_*` views, which hide everything unpublished.

   If the hosting lets you run `GRANT` statements, apply `db/grants.sql` instead (with the real user names) and keep `DB_PUBLIC_WRITES=read`: the database itself then forbids the public API to read anything unpublished.

4. **Paths**: connect once with `ssh user@host` and run `pwd` in the site folder to get the **absolute paths** used below.

## 2. First installation, once, from SSH

```bash
mkdir -p ~/sites/riskstudio-app
cd ~/sites/riskstudio-app
nano .env
chmod 600 .env
```

The application folder sits **next to** the web root, never inside it. `.env` (template: `api/.env.example`):

```ini
APP_ENV=prod
APP_VERSION=5.0.0
API_BASE_PATH=/api
APP_SECRET=<64 hexadecimal characters: php -r 'echo bin2hex(random_bytes(32));'>
DB_HOST=<host shown by the Manager>
DB_PORT=3306
DB_NAME=<database>
DB_PUBLIC_WRITES=write
DB_READ_USER=...
DB_READ_PASSWORD=...
DB_WRITE_USER=...
DB_WRITE_PASSWORD=...
DB_ADMIN_USER=...
DB_ADMIN_PASSWORD=...
COLLECTOR_TIME_BUDGET=50
COLLECTOR_BACKFILL_DAYS=30
COLLECTOR_LEAK_COUNTRIES=BE,FR,NL,LU,DE
NVD_API_KEY=
```

The deployment refuses to run until this file exists, and never reads or overwrites it.

## 3. GitHub, once

1. **Deploy key**, on your computer:

   ```bash
   ssh-keygen -t ed25519 -f riskstudio_deploy -C "github-actions riskstudio" -N ""
   ```

   Add `riskstudio_deploy.pub` to the SSH account in the Infomaniak Manager.

2. **Host fingerprint**, so the workflow refuses any other server:

   ```bash
   ssh-keyscan -p 22 <ssh host> > known_hosts.txt
   ```

3. In the repository, *Settings > Environments > New environment*, name it `production`. Optionally add yourself as **required reviewer**: every deployment then waits for your approval.

   | Kind | Name | Value |
   |---|---|---|
   | Secret | `INFOMANIAK_SSH_KEY` | content of `riskstudio_deploy` (private key) |
   | Secret | `INFOMANIAK_KNOWN_HOSTS` | content of `known_hosts.txt` |
   | Variable | `INFOMANIAK_SSH_HOST` | SSH host from the Manager |
   | Variable | `INFOMANIAK_SSH_USER` | SSH user |
   | Variable | `INFOMANIAK_SSH_PORT` | `22` unless told otherwise |
   | Variable | `INFOMANIAK_APP_DIR` | absolute path of `riskstudio-app` |
   | Variable | `INFOMANIAK_WEB_DIR` | absolute path of the site web root |
   | Variable | `INFOMANIAK_APP_FROM_WEB` | path of the app seen from the web root, default `../riskstudio-app` |
   | Variable | `PUBLIC_URL` | `https://riskstudio.example.org` |

   Then delete `riskstudio_deploy` and `known_hosts.txt` from your computer, or keep the private key in your password manager.

## 4. Deploy

*Actions > Deploy to Infomaniak > Run workflow*, type `deploy`. The workflow:

1. runs the unit tests and the type check;
2. generates the SBOM and the release package (`scripts/sbom.sh`, `scripts/package.sh`);
3. checks the server (PHP 8.2+, `pdo_mysql`, `.env` present);
4. saves the current application to `riskstudio-app.previous`;
5. sends the application (`.env` excluded), runs migrations, seeds and the catalogue import;
6. sends the static site (other files of the web root, such as `.well-known`, are left alone);
7. smoke-tests `/api/v1/health`, the home page and the catalogue.

The release and its SBOM are kept 90 days as workflow artifacts.

## 5. After the first deployment, from SSH

```bash
cd ~/sites/riskstudio-app
php bin/admin.php create you@example.org "Your Name"
php bin/collect.php --force
```

The first command asks the password (14 characters minimum) and prints the TOTP key for your authenticator app. The second runs the collector once and imports 30 days of history.

Then, in the Manager, create the **scheduled task** every 15 minutes:

```bash
php /absolute/path/to/riskstudio-app/bin/collect.php
```

Keep `COLLECTOR_TIME_BUDGET` (50 s) below the maximum duration the hosting allows for scheduled tasks. Overlapping runs exit immediately (database lock). Every run is journaled (back office, *Sources* tab), 30 days kept. Exit code: 0 success, 2 a source failed, 1 configuration error.

Optional:
- a free NVD API key in `NVD_API_KEY` completes CVSS scores 8 times faster;
- the **CCB** source is disabled because the CCB site rejects some data centres. Test from SSH with `curl -I https://ccb.belgium.be/advisories`; if it answers 200, enable it in the *Sources* tab.

## 6. Rollback

```bash
cd ~/sites
rm -rf riskstudio-app && mv riskstudio-app.previous riskstudio-app
```

Migrations only add things (tables, columns, views), so the previous application keeps working on the newer schema. The static site of the previous release comes back by running the workflow on the previous commit.

## 7. Deploying from a computer (without GitHub Actions)

With SSH access configured on the computer:

```bash
make release
DEPLOY_HOST=… DEPLOY_USER=… DEPLOY_APP_DIR=/abs/riskstudio-app DEPLOY_WEB_DIR=/abs/site DEPLOY_URL=https://… scripts/deploy.sh
```

## What was verified before the first real deployment

The package and `scripts/deploy.sh` were run against a local Apache 2.4 + mod_php 8.3 + MariaDB, over HTTPS, with the Infomaniak layout (application outside the web root, `.htaccess` only):

- first installation refused without `.env`; deployment; second deployment with backup;
- `.env` preserved and set to 600; foreign files of the web root preserved; unsafe paths refused;
- HTTPS redirect (API included), security headers without duplicates, immutable cache for bundles, `.htaccess` and stray PHP files forbidden;
- `__Host-` admin cookie, and the full browser walkthrough (proposal, login with TOTP, moderation, logout).

Not verified: the SSH transport itself (the test session could not run an SSH server; a local shim replaced `ssh`), and Infomaniak specifics (PHP CLI name, database host, scheduled task limits). The first real deployment should be watched.
