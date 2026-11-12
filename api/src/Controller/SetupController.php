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
 *   POST /v1/setup/admin    first administrator only, returns the TOTP key once
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
        $pdo = $this->db->connection(Database::ADMIN);
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
        $migrator = new Migrator($this->db->connection(Database::ADMIN), $this->dbDir . '/migrations');
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
