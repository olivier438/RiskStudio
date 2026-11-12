<?php

/**
 * Administrator accounts, from the command line only (no sign-up page, no
 * attack surface). Runs as the DB_WRITE_* user.
 *
 *   php api/bin/admin.php create <email> "<Display name>"   asks the password, prints the TOTP key
 *   php api/bin/admin.php password <email>                    sets a new password
 *   php api/bin/admin.php reset-totp <email>                  new TOTP key, closes sessions
 *   php api/bin/admin.php disable <email> | enable <email>
 *   php api/bin/admin.php list
 *
 * The password is read without echo, or from RS_ADMIN_PASSWORD (automation).
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$appRoot = dirname(__DIR__);
require $appRoot . '/vendor/autoload.php';

use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Security\AdminAuth;
use RiskStudio\Security\Totp;

const MIN_PASSWORD = 14;

function fail(string $message): never
{
    fwrite(STDERR, $message . PHP_EOL);
    exit(1);
}

function readPassword(): string
{
    $fromEnv = getenv('RS_ADMIN_PASSWORD');
    if (is_string($fromEnv) && $fromEnv !== '') {
        return $fromEnv;
    }
    $ask = static function (string $prompt): string {
        fwrite(STDOUT, $prompt);
        $tty = stream_isatty(STDIN);
        $tty && shell_exec('stty -echo');
        $value = rtrim((string) fgets(STDIN), "\r\n");
        $tty && shell_exec('stty echo');
        fwrite(STDOUT, PHP_EOL);

        return $value;
    };
    $password = $ask('Password (' . MIN_PASSWORD . ' characters minimum): ');
    if ($ask('Again: ') !== $password) {
        fail('Passwords differ.');
    }

    return $password;
}

function checkPassword(string $password): void
{
    if (mb_strlen($password) < MIN_PASSWORD) {
        fail('Password too short: ' . MIN_PASSWORD . ' characters minimum (a passphrase is fine).');
    }
}

function printTotp(string $email, string $secret): void
{
    $groups = implode(' ', str_split($secret, 4));
    $uri = Totp::uri($secret, $email);
    fwrite(STDOUT, <<<TXT

    Add this key to an authenticator app (Aegis, 2FAS, Microsoft or Google Authenticator...):
      Account : Risk Studio ({$email})
      Key     : {$groups}
      Type    : time-based, 6 digits, 30 seconds
    Or open this URI with the app:
      {$uri}

    This key is shown once. Store it in your password manager.

    TXT);
}

[$command, $email, $name] = array_pad(array_slice($argv, 1), 3, null);
$email = $email === null ? null : mb_strtolower(trim($email));
$pdo = (new Database(Config::fromFile($appRoot . '/.env')))->connection(Database::WRITE);

$find = static function (string $email) use ($pdo): array {
    $stmt = $pdo->prepare('SELECT * FROM admins WHERE email = ?');
    $stmt->execute([$email]);

    return $stmt->fetch() ?: fail("No administrator {$email}.");
};
$audit = static function (string $action, string $email) use ($pdo): void {
    $pdo->prepare("INSERT INTO audit_log (actor_type, action, entity, entity_id, details) VALUES ('system', ?, 'admin', ?, ?)")
        ->execute([$action, $email, json_encode(['via' => 'cli'])]);
};

switch ($command) {
    case 'create':
        if ($email === null || filter_var($email, FILTER_VALIDATE_EMAIL) === false || $name === null || trim($name) === '') {
            fail('Usage: admin.php create <email> "<Display name>"');
        }
        $password = readPassword();
        checkPassword($password);
        $secret = Totp::generateSecret();
        $pdo->prepare('INSERT INTO admins (email, display_name, password_hash, totp_secret) VALUES (?, ?, ?, ?)')
            ->execute([$email, mb_substr(trim($name), 0, 100), AdminAuth::hashPassword($password), $secret]);
        $audit('admin.create', $email);
        fwrite(STDOUT, "Administrator {$email} created." . PHP_EOL);
        printTotp($email, $secret);
        break;

    case 'password':
        $admin = $find((string) $email);
        $password = readPassword();
        checkPassword($password);
        $pdo->prepare('UPDATE admins SET password_hash = ? WHERE id = ?')->execute([AdminAuth::hashPassword($password), $admin['id']]);
        $pdo->prepare('DELETE FROM admin_sessions WHERE admin_id = ?')->execute([$admin['id']]);
        $audit('admin.password', (string) $email);
        fwrite(STDOUT, 'Password changed, sessions closed.' . PHP_EOL);
        break;

    case 'reset-totp':
        $admin = $find((string) $email);
        $secret = Totp::generateSecret();
        $pdo->prepare('UPDATE admins SET totp_secret = ?, totp_last_step = NULL WHERE id = ?')->execute([$secret, $admin['id']]);
        $pdo->prepare('DELETE FROM admin_sessions WHERE admin_id = ?')->execute([$admin['id']]);
        $audit('admin.reset_totp', (string) $email);
        printTotp((string) $email, $secret);
        break;

    case 'disable':
    case 'enable':
        $admin = $find((string) $email);
        $pdo->prepare('UPDATE admins SET is_active = ? WHERE id = ?')->execute([(int) ($command === 'enable'), $admin['id']]);
        $pdo->prepare('DELETE FROM admin_sessions WHERE admin_id = ?')->execute([$admin['id']]);
        $audit("admin.{$command}", (string) $email);
        fwrite(STDOUT, "Administrator {$email} {$command}d." . PHP_EOL);
        break;

    case 'list':
        foreach ($pdo->query('SELECT email, display_name, is_active, last_login_at FROM admins ORDER BY email') as $a) {
            fwrite(STDOUT, sprintf("%-40s %-25s %-8s last login %s\n", $a['email'], $a['display_name'],
                $a['is_active'] ? 'active' : 'disabled', $a['last_login_at'] ?? 'never'));
        }
        break;

    default:
        fail('Commands: create, password, reset-totp, disable, enable, list (see the header of this file).');
}
