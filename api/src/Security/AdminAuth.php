<?php

declare(strict_types=1);

namespace RiskStudio\Security;

use PDO;
use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;

/**
 * Administrator authentication: e-mail + password (argon2id) + TOTP, all
 * three required. Sessions are random tokens kept in `admin_sessions`
 * (hashed), with an idle timeout and an absolute lifetime. Every mutating
 * request must also carry the session CSRF token in `X-CSRF-Token`.
 */
final class AdminAuth
{
    public const IDLE_MINUTES = 30;
    public const LIFETIME_HOURS = 8;
    private const LOGIN_WINDOW = 900;
    private const MAX_PER_ACCOUNT = 5;
    private const MAX_PER_IP = 20;

    /** Used when the e-mail is unknown, so timing does not reveal accounts. */
    private const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$Sk5KRjJyUWt2eVp6RlBrcQ$5AAS9chXGZ7C6rCsH9V9LsWouLf0/i3/Y/Be3z+kuaM';

    public function __construct(
        private readonly PDO $pdo,
        private readonly RateLimiter $limiter,
        private readonly bool $secureCookie,
    ) {
    }

    public function cookieName(): string
    {
        return $this->secureCookie ? '__Host-rs_admin' : 'rs_admin';
    }

    public function secureCookie(): bool
    {
        return $this->secureCookie;
    }

    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID);
    }

    /**
     * @return array{token: string, csrf: string, admin: array<string, mixed>}
     */
    public function login(string $email, string $password, string $code, string $ip): array
    {
        $email = mb_strtolower(trim($email));
        if ($this->limiter->count('login-account', $email, self::LOGIN_WINDOW) >= self::MAX_PER_ACCOUNT
            || $this->limiter->count('login-ip', $ip, self::LOGIN_WINDOW) >= self::MAX_PER_IP) {
            throw new HttpException(429, 'too_many_attempts', 'Trop de tentatives. Réessayez dans 15 minutes.');
        }

        $stmt = $this->pdo->prepare('SELECT * FROM admins WHERE email = ? AND is_active = 1');
        $stmt->execute([$email]);
        $admin = $stmt->fetch() ?: null;

        $passwordOk = password_verify($password, $admin['password_hash'] ?? self::DUMMY_HASH);
        $step = null;
        if ($admin !== null && $passwordOk && $admin['totp_secret'] !== null) {
            $last = $admin['totp_last_step'] === null ? null : (int) $admin['totp_last_step'];
            $step = Totp::verify((string) $admin['totp_secret'], $code, $last);
        }

        if ($admin === null || !$passwordOk || $step === null) {
            $this->limiter->hit('login-account', $email, self::MAX_PER_ACCOUNT, self::LOGIN_WINDOW);
            $this->limiter->hit('login-ip', $ip, self::MAX_PER_IP, self::LOGIN_WINDOW);
            $this->audit($admin === null ? null : (int) $admin['id'], 'admin.login_failed', ['reason' => 'credentials']);
            throw new HttpException(401, 'invalid_credentials', 'Identifiants ou code invalides.');
        }

        $this->limiter->reset('login-account', $email);
        if (password_needs_rehash((string) $admin['password_hash'], PASSWORD_ARGON2ID)) {
            $this->pdo->prepare('UPDATE admins SET password_hash = ? WHERE id = ?')
                ->execute([self::hashPassword($password), $admin['id']]);
        }
        $this->pdo->prepare('UPDATE admins SET totp_last_step = ?, last_login_at = UTC_TIMESTAMP() WHERE id = ?')
            ->execute([$step, $admin['id']]);

        $token = bin2hex(random_bytes(32));
        $csrf = bin2hex(random_bytes(32));
        $this->pdo->prepare(
            'INSERT INTO admin_sessions (token_hash, admin_id, csrf_token, expires_at)
             VALUES (?, ?, ?, UTC_TIMESTAMP() + INTERVAL ' . self::LIFETIME_HOURS . ' HOUR)'
        )->execute([hash('sha256', $token), $admin['id'], $csrf]);
        $this->pdo->exec('DELETE FROM admin_sessions WHERE expires_at < UTC_TIMESTAMP()');
        $this->audit((int) $admin['id'], 'admin.login', []);

        return ['token' => $token, 'csrf' => $csrf, 'admin' => self::publicAdmin($admin)];
    }

    /**
     * The administrator behind the request, or null. Mutating requests must
     * carry the CSRF token; otherwise 403.
     *
     * @return array{admin: array<string, mixed>, csrf: string, token_hash: string}|null
     */
    public function authenticate(Request $request): ?array
    {
        $token = $request->cookie($this->cookieName());
        if ($token === null || !preg_match('/^[0-9a-f]{64}$/', $token)) {
            return null;
        }
        $hash = hash('sha256', $token);
        $stmt = $this->pdo->prepare(
            'SELECT s.csrf_token, a.* FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
             WHERE s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP()
               AND s.last_seen_at > UTC_TIMESTAMP() - INTERVAL ' . self::IDLE_MINUTES . ' MINUTE
               AND a.is_active = 1'
        );
        $stmt->execute([$hash]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        if (!in_array($request->method, ['GET', 'HEAD'], true)) {
            $sent = $request->header('x-csrf-token') ?? '';
            if (!hash_equals((string) $row['csrf_token'], $sent)) {
                throw new HttpException(403, 'csrf', 'Jeton CSRF manquant ou invalide.');
            }
        }
        $this->pdo->prepare('UPDATE admin_sessions SET last_seen_at = UTC_TIMESTAMP() WHERE token_hash = ?')->execute([$hash]);

        return ['admin' => self::publicAdmin($row), 'csrf' => (string) $row['csrf_token'], 'token_hash' => $hash];
    }

    public function logout(string $tokenHash): void
    {
        $this->pdo->prepare('DELETE FROM admin_sessions WHERE token_hash = ?')->execute([$tokenHash]);
    }

    /** @param array<string, mixed> $details */
    public function audit(?int $adminId, string $action, array $details, string $entity = 'admin', ?string $entityId = null): void
    {
        $this->pdo->prepare(
            "INSERT INTO audit_log (actor_type, actor_id, action, entity, entity_id, details) VALUES ('admin', ?, ?, ?, ?, ?)"
        )->execute([$adminId, $action, $entity, $entityId, json_encode($details, JSON_UNESCAPED_UNICODE)]);
    }

    /** @param array<string, mixed> $row @return array<string, mixed> */
    private static function publicAdmin(array $row): array
    {
        return ['id' => (int) $row['id'], 'email' => $row['email'], 'display_name' => $row['display_name']];
    }
}
