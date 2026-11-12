<?php

declare(strict_types=1);

namespace RiskStudio\Controller;

use RiskStudio\Collector\Factory;
use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;

/**
 * Web trigger of the collector, for the Infomaniak task planner of shared
 * hosting, which calls a URL (every 15 minutes at most).
 *
 * Disabled (404) unless CRON_KEY (32+ characters) is set in .env. The key is
 * the password of the URL (HTTP Basic, any user name: the planner's
 * "password-protected URL" option), or `?key=` as a fallback.
 */
final class CronController
{
    public function __construct(
        private readonly Config $config,
        private readonly Database $db,
        private readonly string $dbDir,
    ) {
    }

    public function collect(Request $request): Response
    {
        $key = (string) $this->config->get('CRON_KEY', '');
        if (strlen($key) < 32) {
            throw HttpException::notFound('Unknown endpoint.');
        }
        if (!hash_equals($key, self::presentedKey($request))) {
            usleep(random_int(800_000, 1_200_000));

            return Response::error(401, 'unauthorized', 'Invalid key.')
                ->withHeader('WWW-Authenticate', 'Basic realm="Risk Studio collector"');
        }

        // The planner may close the connection before the end: keep going.
        ignore_user_abort(true);
        $budget = (int) $this->config->get('COLLECTOR_TIME_BUDGET', '50');
        $limit = (int) ini_get('max_execution_time');
        if ($limit > 0) {
            @set_time_limit($budget + 30);
            $limit = (int) ini_get('max_execution_time');
            $budget = min($budget, max(10, $limit - 10));
        }

        $summary = Factory::collector($this->config, $this->db->connection(Database::WRITE), $this->dbDir, $budget)->run();
        $failed = array_keys(array_filter($summary, static fn (array $s): bool => ($s['status'] ?? '') === 'failed'));

        return Response::json([
            'ok' => $failed === [],
            'failed' => $failed,
            'sources' => array_map(static fn (array $s): array => array_intersect_key($s, array_flip(['status', 'new', 'updated', 'unchanged', 'completed'])), $summary),
        ], $failed === [] ? 200 : 502)->withHeader('Cache-Control', 'no-store');
    }

    private static function presentedKey(Request $request): string
    {
        $auth = $request->header('authorization') ?? '';
        if (stripos($auth, 'basic ') === 0) {
            $decoded = base64_decode(substr($auth, 6), true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                return explode(':', $decoded, 2)[1];
            }
        }

        return (string) $request->query('key');
    }
}
