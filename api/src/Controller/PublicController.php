<?php

declare(strict_types=1);

namespace RiskStudio\Controller;

use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;
use RiskStudio\Repository\FeedFilter;
use RiskStudio\Repository\IntelRepository;
use RiskStudio\Repository\LeakRepository;
use RiskStudio\Repository\ReferenceRepository;
use RiskStudio\Repository\RiskFilter;
use RiskStudio\Repository\RiskRepository;
use RiskStudio\Repository\StatsRepository;

/** Public, read-only endpoints. Every query runs as the `rs_read` database user. */
final class PublicController
{
    public function __construct(
        private readonly Config $config,
        private readonly Database $db,
    ) {
    }

    public function health(Request $request): Response
    {
        $database = 'ok';
        try {
            $this->db->connection(Database::READ)->query('SELECT 1')->fetchColumn();
        } catch (\Throwable $e) {
            error_log('[riskstudio] health check: database unavailable: ' . $e->getMessage());
            $database = 'unavailable';
        }

        return Response::json([
            'status' => $database === 'ok' ? 'ok' : 'degraded',
            'version' => $this->config->get('APP_VERSION', '5.0.0'),
            'database' => $database,
            'time' => gmdate('Y-m-d\TH:i:s\Z'),
        ], $database === 'ok' ? 200 : 503);
    }

    public function reference(Request $request): Response
    {
        $repo = new ReferenceRepository($this->db->connection(Database::READ));

        return Response::json([
            'categories' => $repo->categories(),
            'sectors' => $repo->sectors(),
            'frameworks' => $repo->frameworks(),
            'sources' => (new StatsRepository($this->db->connection(Database::READ)))->sources(),
        ], 200, 300)->withETag($request);
    }

    public function controls(Request $request): Response
    {
        $code = strtoupper($request->params['code'] ?? '');
        $controls = (new ReferenceRepository($this->db->connection(Database::READ)))->controls($code);
        if ($controls === null) {
            throw HttpException::notFound('Unknown framework.');
        }

        return Response::json(['framework' => $code, 'controls' => $controls], 200, 300)->withETag($request);
    }

    public function risks(Request $request): Response
    {
        $filter = RiskFilter::fromRequest($request);
        $result = (new RiskRepository($this->db->connection(Database::READ)))->search($filter);

        return Response::json([
            'data' => $result['items'],
            'meta' => [
                'total' => $result['total'],
                'page' => $filter->page,
                'per_page' => $filter->perPage,
                'pages' => (int) ceil($result['total'] / $filter->perPage),
            ],
        ])->withETag($request);
    }

    public function risk(Request $request): Response
    {
        $code = strtoupper($request->params['code'] ?? '');
        $risk = (new RiskRepository($this->db->connection(Database::READ)))->findByCode($code);
        if ($risk === null) {
            throw HttpException::notFound('Unknown risk.');
        }

        return Response::json(['data' => $risk])->withETag($request);
    }

    public function stats(Request $request): Response
    {
        return Response::json((new StatsRepository($this->db->connection(Database::READ)))->summary())
            ->withETag($request);
    }

    public function intel(Request $request): Response
    {
        $filter = FeedFilter::fromRequest($request);
        $result = (new IntelRepository($this->db->connection(Database::READ)))->search($filter);

        return $this->page($request, $result, $filter);
    }

    public function intelItem(Request $request): Response
    {
        $id = $request->params['id'] ?? '';
        if (!ctype_digit($id) || strlen($id) > 18) {
            throw HttpException::notFound('Unknown item.');
        }
        $item = (new IntelRepository($this->db->connection(Database::READ)))->find((int) $id);
        if ($item === null) {
            throw HttpException::notFound('Unknown item.');
        }

        return Response::json(['data' => $item])->withETag($request);
    }

    public function leaks(Request $request): Response
    {
        $filter = FeedFilter::fromRequest($request);
        $result = (new LeakRepository($this->db->connection(Database::READ)))->search($filter);

        return $this->page($request, $result, $filter);
    }

    /** @param array{items: list<array<string, mixed>>, total: int} $result */
    private function page(Request $request, array $result, FeedFilter $filter): Response
    {
        return Response::json([
            'data' => $result['items'],
            'meta' => [
                'total' => $result['total'],
                'page' => $filter->page,
                'per_page' => $filter->perPage,
                'pages' => (int) ceil($result['total'] / $filter->perPage),
            ],
        ])->withETag($request);
    }
}
