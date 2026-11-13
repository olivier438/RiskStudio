<?php

declare(strict_types=1);

namespace RiskStudio\Controller;

use RiskStudio\Collector\Classifier;
use RiskStudio\Collector\Probe;
use RiskStudio\Collector\PublicAddress;
use RiskStudio\Collector\Rules;
use RiskStudio\Collector\SourceConfig;
use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;
use RiskStudio\Repository\AdminRepository;
use RiskStudio\Repository\ValidationException;
use RiskStudio\Security\AdminAuth;

/**
 * Back-office endpoints under /v1/admin. Every endpoint except login requires
 * a valid session; mutating ones also require the CSRF token. Responses are
 * never cached. Every decision is written to the audit log.
 */
final class AdminController
{
    public function __construct(
        private readonly AdminAuth $auth,
        private readonly AdminRepository $repo,
        /** db/rules, for the classification preview of a feed being added. */
        private readonly string $rulesDir = '',
    ) {
    }

    public function login(Request $request): Response
    {
        $body = $request->json();
        $session = $this->auth->login(
            is_string($body['email'] ?? null) ? $body['email'] : '',
            is_string($body['password'] ?? null) ? $body['password'] : '',
            is_string($body['code'] ?? null) ? $body['code'] : '',
            $request->ip,
        );

        return self::private(['admin' => $session['admin'], 'csrf' => $session['csrf']])
            ->withCookie($this->auth->cookieName(), $session['token'], AdminAuth::LIFETIME_HOURS * 3600, $this->auth->secureCookie());
    }

    public function logout(Request $request): Response
    {
        $session = $this->session($request);
        $this->auth->logout($session['token_hash']);
        $this->auth->audit($session['admin']['id'], 'admin.logout', []);

        return self::private(['ok' => true])->withCookie($this->auth->cookieName(), '', 0, $this->auth->secureCookie());
    }

    public function me(Request $request): Response
    {
        $session = $this->session($request);

        return self::private(['admin' => $session['admin'], 'csrf' => $session['csrf'], 'queue' => $this->repo->queueCounts()]);
    }

    public function queue(Request $request): Response
    {
        $this->session($request);

        return self::private([
            'counts' => $this->repo->queueCounts(),
            'intel' => $this->repo->pendingIntel(),
            'leaks' => $this->repo->pendingLeaks(),
            'proposals' => $this->repo->proposals('pending'),
        ]);
    }

    public function proposalsHistory(Request $request): Response
    {
        $this->session($request);
        $status = $request->query('status') ?? 'approved';
        if (!in_array($status, ['approved', 'rejected'], true)) {
            throw HttpException::badRequest('status must be approved or rejected.');
        }

        return self::private(['data' => $this->repo->proposals($status)]);
    }

    public function decideIntel(Request $request): Response
    {
        return $this->decideFeed($request, 'intel_items', 'intel');
    }

    public function decideLeak(Request $request): Response
    {
        return $this->decideFeed($request, 'leaks', 'leak');
    }

    private function decideFeed(Request $request, string $table, string $entity): Response
    {
        $session = $this->session($request);
        $id = self::id($request);
        $body = $request->json();
        $decision = is_string($body['decision'] ?? null) ? $body['decision'] : '';
        $previous = $this->repo->decideFeed($table, $id, $decision);
        $this->auth->audit($session['admin']['id'], "{$entity}.{$decision}", [
            'previous_status' => $previous,
            'note' => self::note($body),
        ], $entity, (string) $id);

        return self::private(['ok' => true, 'counts' => $this->repo->queueCounts()]);
    }

    public function decideProposal(Request $request): Response
    {
        $session = $this->session($request);
        $id = self::id($request);
        $body = $request->json();
        $decision = is_string($body['decision'] ?? null) ? $body['decision'] : '';
        $result = $this->repo->decideProposal($id, $decision, $session['admin']['id'], self::note($body));
        $this->auth->audit($session['admin']['id'], "proposal.{$decision}", [
            'kind' => $result['proposal']['kind'],
            'risk_code' => $result['risk_code'],
            'note' => self::note($body),
        ], 'proposal', (string) $id);

        return self::private(['ok' => true, 'risk_code' => $result['risk_code'], 'counts' => $this->repo->queueCounts()]);
    }

    public function risks(Request $request): Response
    {
        $this->session($request);
        $origin = $request->query('origin');
        if ($origin !== null && !in_array($origin, ['catalogue', 'community'], true)) {
            throw HttpException::badRequest('origin must be catalogue or community.');
        }

        return self::private(['data' => $this->repo->risks($origin)]);
    }

    public function risk(Request $request): Response
    {
        $this->session($request);

        return self::private(['data' => $this->repo->communityRisk(strtoupper($request->params['code'] ?? ''))]);
    }

    public function updateRisk(Request $request): Response
    {
        $session = $this->session($request);
        $code = strtoupper($request->params['code'] ?? '');
        $this->repo->updateCommunityRisk($code, $request->json());
        $this->auth->audit($session['admin']['id'], 'risk.update', [], 'risk', $code);

        return self::private(['ok' => true, 'data' => $this->repo->communityRisk($code)]);
    }

    public function sources(Request $request): Response
    {
        $this->session($request);

        return self::private(['data' => $this->repo->sources()]);
    }

    public function updateSource(Request $request): Response
    {
        $session = $this->session($request);
        $code = strtoupper($request->params['code'] ?? '');
        $body = $request->json();
        $previous = $this->repo->updateSource($code, $body);
        $this->auth->audit($session['admin']['id'], 'source.update', [
            'previous' => $previous,
            'changes' => array_intersect_key($body, ['enabled' => 1, 'authoritative' => 1]),
        ], 'source', $code);

        return self::private(['ok' => true, 'data' => $this->repo->sources()]);
    }

    /** Tests a source from this server with its real parser; stores nothing. */
    public function probeSource(Request $request): Response
    {
        $session = $this->session($request);
        $code = strtoupper($request->params['code'] ?? '');
        $source = array_values(array_filter($this->repo->sources(), static fn (array $s): bool => $s['code'] === $code))[0]
            ?? throw HttpException::notFound('Unknown source.');
        @set_time_limit(90);
        $config = $source['config'] === null ? null : json_encode($source['config'], JSON_UNESCAPED_UNICODE);
        $report = (new Probe())->source($code, (string) $source['url'], $config);
        $this->auth->audit($session['admin']['id'], 'source.probe', self::probeSummary($report), 'source', $code);

        return self::private(['data' => $report]);
    }

    /** Reads a feed being added and shows how its entries would be classified. Stores nothing. */
    public function previewSource(Request $request): Response
    {
        $session = $this->session($request);
        $body = $request->json();
        $source = AdminRepository::customSourceInput(['name' => 'Aperçu'] + $body);
        $config = SourceConfig::fromInput($body);
        @set_time_limit(60);
        $report = (new Probe())->preview($source['url'], $config, new Classifier(Rules::load($this->rulesDir)));
        $this->auth->audit($session['admin']['id'], 'source.preview', ['url' => $source['url'], 'verdict' => $report['verdict'], 'kept' => $report['kept']], 'url', null);

        return self::private(['data' => $report]);
    }

    /** Adds an RSS or Atom source, no code needed. */
    public function createSource(Request $request): Response
    {
        $session = $this->session($request);
        $body = $request->json();
        $source = AdminRepository::customSourceInput($body);
        $config = SourceConfig::fromInput($body)->toArray();
        self::assertPublic($source['url']);
        $code = $this->repo->createCustomSource($source, $config);
        $this->auth->audit($session['admin']['id'], 'source.create', $source + ['config' => $config], 'source', $code);

        return self::private(['ok' => true, 'code' => $code, 'data' => $this->repo->sources()]);
    }

    public function editSource(Request $request): Response
    {
        $session = $this->session($request);
        $code = strtoupper($request->params['code'] ?? '');
        $body = $request->json();
        $source = AdminRepository::customSourceInput($body);
        $config = SourceConfig::fromInput($body)->toArray();
        self::assertPublic($source['url']);
        $previous = $this->repo->updateCustomSource($code, $source, $config);
        $this->auth->audit($session['admin']['id'], 'source.edit', ['previous' => $previous, 'new' => $source + ['config' => $config]], 'source', $code);

        return self::private(['ok' => true, 'data' => $this->repo->sources()]);
    }

    public function deleteSource(Request $request): Response
    {
        $session = $this->session($request);
        $code = strtoupper($request->params['code'] ?? '');
        $previous = $this->repo->deleteCustomSource($code);
        $this->auth->audit($session['admin']['id'], 'source.delete', ['previous' => $previous], 'source', $code);

        return self::private(['ok' => true, 'data' => $this->repo->sources()]);
    }

    private static function assertPublic(string $url): void
    {
        try {
            PublicAddress::check($url);
        } catch (\InvalidArgumentException $e) {
            throw new ValidationException(['url' => $e->getMessage()]);
        }
    }

    /** Tests any public HTTPS address from this server (candidate sources). */
    public function probeUrl(Request $request): Response
    {
        $session = $this->session($request);
        $url = trim(is_string($request->json()['url'] ?? null) ? $request->json()['url'] : '');
        if ($url === '') {
            throw HttpException::badRequest('url is required.');
        }
        @set_time_limit(60);
        $report = (new Probe())->url($url);
        $this->auth->audit($session['admin']['id'], 'url.probe', ['url' => mb_substr($url, 0, 500)] + self::probeSummary($report), 'url', null);

        return self::private(['data' => $report]);
    }

    /** @param array<string, mixed> $report @return array<string, mixed> */
    private static function probeSummary(array $report): array
    {
        return ['verdict' => $report['verdict'], 'status' => $report['requests'][0]['status'] ?? null, 'items' => $report['items'] ?? null];
    }

    public function statistics(Request $request): Response
    {
        $this->session($request);

        return self::private($this->repo->statistics());
    }

    public function audit(Request $request): Response
    {
        $this->session($request);

        return self::private(['data' => $this->repo->audit($request->queryInt('limit', 100, 1, 500))]);
    }

    // -------------------------------------------------------------------------

    /** @return array{admin: array<string, mixed>, csrf: string, token_hash: string} */
    private function session(Request $request): array
    {
        return $this->auth->authenticate($request)
            ?? throw new HttpException(401, 'unauthenticated', 'Session absente ou expirée.');
    }

    private static function id(Request $request): int
    {
        $id = $request->params['id'] ?? '';
        if (!ctype_digit($id) || strlen($id) > 18) {
            throw HttpException::notFound('Unknown item.');
        }

        return (int) $id;
    }

    /** @param array<string, mixed> $body */
    private static function note(array $body): ?string
    {
        $note = is_string($body['note'] ?? null) ? trim($body['note']) : '';

        return $note === '' ? null : mb_substr($note, 0, 1000);
    }

    /** @param array<string, mixed> $data */
    private static function private(array $data, int $status = 200): Response
    {
        return Response::json($data, $status)->withHeader('Cache-Control', 'no-store');
    }
}
