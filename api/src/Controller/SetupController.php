<?php

declare(strict_types=1);

namespace RiskStudio\Controller;

use RiskStudio\Catalogue\CatalogueImporter;
use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;
use RiskStudio\Migrator;
use RiskStudio\Security\AdminAuth;
use RiskStudio\Security\Totp;

/**
 * Web installer for hosting reached by FTP only (no SSH, no PHP CLI).
 *
 * Disabled unless SETUP_TOKEN (32+ characters) is set in the server .env:
 * every endpoint then answers 404, as if it did not exist. With the token:
 *   GET  /v1/setup/status   schema and accounts state
 *   POST /v1/setup/install  migrations, seeds, catalogue import (idempotent)
 *                           with the schema owner typed in the form
 *                           (db_admin_user / db_admin_password), used for
 *                           this request only, never stored or logged
 *   POST /v1/setup/admin    first administrator only, returns the TOTP key once
 *   POST /v1/setup/admin/reset  new TOTP key for an existing administrator,
 *                           after checking e-mail + password; closes the
 *                           sessions and lifts a login lockout
 * Remove SETUP_TOKEN from .env once done.
 */
final class SetupController
{
    public function __construct(
        private readonly Config $config,
        private readonly Database $db,
        private readonly string $dbDir,
    ) {
    }

    public function status(Request $request): Response
    {
        $this->guard($request);
        // Read-write account: enough to inspect, never the schema owner.
        $pdo = $this->db->connection(Database::WRITE);
        $tables = $pdo->query('SHOW TABLES')->fetchAll(\PDO::FETCH_COLUMN);
        $installed = in_array('schema_migrations', $tables, true);
        $applied = $installed ? $pdo->query('SELECT version FROM schema_migrations')->fetchAll(\PDO::FETCH_COLUMN) : [];
        $available = array_map(static fn (string $f): string => basename($f, '.sql'), glob($this->dbDir . '/migrations/*.sql') ?: []);

        return self::private([
            'installed' => $installed,
            'migrations_applied' => count($applied),
            'migrations_pending' => array_values(array_diff($available, $applied)),
            'risks' => $installed && in_array('risks', $tables, true)
                ? (int) $pdo->query("SELECT COUNT(*) FROM risks WHERE status = 'published'")->fetchColumn() : 0,
            'admins' => $installed && in_array('admins', $tables, true)
                ? (int) $pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn() : 0,
            'php' => PHP_VERSION,
        ]);
    }

    public function install(Request $request): Response
    {
        $this->guard($request);
        $log = [];
        $append = static function (string $line) use (&$log): void {
            $log[] = $line;
        };
        $migrator = new Migrator($this->ownerConnection($request), $this->dbDir . '/migrations');
        $applied = $migrator->migrate($append);
        $migrator->seed($this->dbDir . '/seeds', $append);
        $stats = (new CatalogueImporter($this->db->connection(Database::WRITE), $this->dbDir . '/catalogue'))->import();
        $append(sprintf('Catalogue : %d risques, %d contrôles, %d correspondances.', $stats['risks'], $stats['controls'], $stats['crosswalk']));

        return self::private(['ok' => true, 'migrations_applied' => $applied, 'log' => $log]);
    }

    public function createAdmin(Request $request): Response
    {
        $this->guard($request);
        $pdo = $this->db->connection(Database::WRITE);
        if ((int) $pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn() > 0) {
            throw new HttpException(409, 'admin_exists', 'Un administrateur existe déjà. Les suivants se créent depuis l’administration ou en ligne de commande.');
        }
        $body = $request->json();
        $email = mb_strtolower(trim(is_string($body['email'] ?? null) ? $body['email'] : ''));
        $name = trim(is_string($body['name'] ?? null) ? $body['name'] : '');
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';
        $errors = [];
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors['email'] = 'Adresse e-mail invalide.';
        }
        if ($name === '' || mb_strlen($name) > 100) {
            $errors['name'] = 'Nom requis, 100 caractères au maximum.';
        }
        if (mb_strlen($password) < 14) {
            $errors['password'] = '14 caractères au minimum (une phrase de passe convient).';
        }
        if ($errors !== []) {
            throw new \RiskStudio\Repository\ValidationException($errors);
        }

        $secret = Totp::generateSecret();
        $pdo->prepare('INSERT INTO admins (email, display_name, password_hash, totp_secret) VALUES (?, ?, ?, ?)')
            ->execute([$email, $name, AdminAuth::hashPassword($password), $secret]);
        $pdo->prepare("INSERT INTO audit_log (actor_type, action, entity, entity_id, details) VALUES ('system', 'admin.create', 'admin', ?, ?)")
            ->execute([$email, json_encode(['via' => 'web setup'])]);

        return self::private(['ok' => true, 'totp_secret' => $secret, 'totp_uri' => Totp::uri($secret, $email)]);
    }

    public function resetAdminTotp(Request $request): Response
    {
        $this->guard($request);
        $pdo = $this->db->connection(Database::WRITE);
        $body = $request->json();
        $email = mb_strtolower(trim(is_string($body['email'] ?? null) ? $body['email'] : ''));
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';

        $stmt = $pdo->prepare('SELECT id, password_hash FROM admins WHERE email = ? AND is_active = 1');
        $stmt->execute([$email]);
        $admin = $stmt->fetch();
        if ($admin === false || !password_verify($password, (string) $admin['password_hash'])) {
            usleep(random_int(800_000, 1_200_000));
            throw new HttpException(401, 'invalid_credentials', 'E-mail ou mot de passe incorrect.');
        }

        $secret = Totp::generateSecret();
        $pdo->prepare('UPDATE admins SET totp_secret = ?, totp_last_step = NULL WHERE id = ?')->execute([$secret, $admin['id']]);
        $pdo->prepare('DELETE FROM admin_sessions WHERE admin_id = ?')->execute([$admin['id']]);
        // Lift the login lockout of this account (its bucket is an HMAC of the e-mail).
        $appSecret = (string) $this->config->get('APP_SECRET', '');
        if (strlen($appSecret) >= 32) {
            (new \RiskStudio\Security\RateLimiter($pdo, $appSecret))->reset('login-account', $email);
        }
        $pdo->prepare("INSERT INTO audit_log (actor_type, action, entity, entity_id, details) VALUES ('system', 'admin.reset_totp', 'admin', ?, ?)")
            ->execute([$email, json_encode(['via' => 'web setup'])]);

        return self::private(['ok' => true, 'totp_secret' => $secret, 'totp_uri' => Totp::uri($secret, $email)]);
    }

    /**
     * The schema owner: credentials typed in the installer (preferred, never
     * stored), or DB_ADMIN_* from .env when present (command-line installs).
     */
    private function ownerConnection(Request $request): \PDO
    {
        $body = $request->body === '' ? [] : $request->json();
        $user = is_string($body['db_admin_user'] ?? null) ? trim($body['db_admin_user']) : '';
        $password = is_string($body['db_admin_password'] ?? null) ? $body['db_admin_password'] : '';

        if ($user === '') {
            if ((string) $this->config->get('DB_ADMIN_USER', '') === '') {
                throw new \RiskStudio\Repository\ValidationException([
                    'db_admin_user' => 'Indiquez l’utilisateur de la base qui a tous les droits.',
                ]);
            }

            return $this->db->connection(Database::ADMIN);
        }
        try {
            return $this->db->connectAs($user, $password);
        } catch (\PDOException) {
            // Never echo the driver message: it may contain the host or user.
            throw new HttpException(400, 'db_admin_refused', 'Connexion refusée avec cet utilisateur de la base : vérifiez l’identifiant et le mot de passe.');
        }
    }

    /** 404 when setup is disabled; 403 on a wrong token, with a delay against guessing. */
    private function guard(Request $request): void
    {
        $token = (string) $this->config->get('SETUP_TOKEN', '');
        if (strlen($token) < 32) {
            throw HttpException::notFound('Unknown endpoint.');
        }
        if (!hash_equals($token, (string) $request->header('x-setup-token'))) {
            usleep(random_int(800_000, 1_200_000));
            throw new HttpException(403, 'setup_token', 'Jeton d’installation incorrect.');
        }
    }

    /** @param array<string, mixed> $data */
    private static function private(array $data): Response
    {
        return Response::json($data)->withHeader('Cache-Control', 'no-store');
    }
}
