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
        // Every presented key is checked: a browser may keep sending old Basic
        // credentials while ?key= carries the right one.
        $candidates = self::presentedKeys($request);
        $valid = false;
        foreach ($candidates as $candidate) {
            $valid = hash_equals($key, $candidate) || $valid;
        }
        if (!$valid) {
            usleep(random_int(800_000, 1_200_000));
            $response = Response::error(
                401,
                $candidates === [] ? 'no_credentials' : 'invalid_key',
                $candidates === [] ? 'Aucun identifiant reçu par le serveur PHP.' : 'Clé incorrecte.',
            );

            // No login popup when the key came in the URL: show the message instead.
            return $request->query('key') !== null
                ? $response
                : $response->withHeader('WWW-Authenticate', 'Basic realm="NOROSHI collector"');
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

    /** @return list<string> keys presented as HTTP Basic password and/or ?key= */
    private static function presentedKeys(Request $request): array
    {
        $keys = [];
        $auth = $request->header('authorization') ?? '';
        if (stripos($auth, 'basic ') === 0) {
            $decoded = base64_decode(substr($auth, 6), true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                $keys[] = explode(':', $decoded, 2)[1];
            }
        }
        $query = $request->query('key');
        if ($query !== null) {
            $keys[] = $query;
        }

        return $keys;
    }
}
