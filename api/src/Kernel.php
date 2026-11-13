<?php

declare(strict_types=1);

namespace RiskStudio;

use RiskStudio\Controller\AdminController;
use RiskStudio\Controller\CronController;
use RiskStudio\Controller\ProposalController;
use RiskStudio\Controller\PublicController;
use RiskStudio\Controller\SetupController;
use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;
use RiskStudio\Http\Router;
use RiskStudio\Repository\AdminRepository;
use RiskStudio\Repository\AlertRepository;
use RiskStudio\Repository\ValidationException;
use RiskStudio\Security\AdminAuth;
use RiskStudio\Security\RateLimiter;

final class Kernel
{
    private readonly Router $router;
    private ?AdminController $admin = null;
    private ?ProposalController $proposals = null;

    public function __construct(
        private readonly Config $config,
        private readonly Database $db,
    ) {
        $this->router = $this->routes();
    }

    private function routes(): Router
    {
        $router = new Router();
        $public = new PublicController($this->config, $this->db);

        $router->get('/v1/health', $public->health(...));
        $router->get('/v1/reference', $public->reference(...));
        $router->get('/v1/frameworks/{code}/controls', $public->controls(...));
        $router->get('/v1/risks', $public->risks(...));
        $router->get('/v1/risks/{code}', $public->risk(...));
        $router->get('/v1/stats', $public->stats(...));
        $router->get('/v1/intel', $public->intel(...));
        $router->get('/v1/intel/{id}', $public->intelItem(...));
        $router->get('/v1/leaks', $public->leaks(...));
        $router->get('/v1/alerts', $public->alerts(...));
        $router->post('/v1/proposals', fn (Request $r) => $this->proposals()->create($r));

        // Web installer (FTP-only hosting): 404 unless SETUP_TOKEN is set.
        $setup = fn (string $method): \Closure => fn (Request $r) => $this->setup()->{$method}($r);
        $router->get('/v1/setup/status', $setup('status'));
        $router->post('/v1/setup/install', $setup('install'));
        $router->post('/v1/setup/admin', $setup('createAdmin'));
        $router->post('/v1/setup/admin/reset', $setup('resetAdminTotp'));

        // Collector trigger for the hosting task planner: 404 unless CRON_KEY is set.
        $cron = fn (Request $r) => (new CronController($this->config, $this->db, $this->dbDir()))->collect($r);
        $router->get('/v1/cron/collect', $cron);
        $router->post('/v1/cron/collect', $cron);

        // Back office: controllers (and their read-write connection) are only
        // created when an admin route is actually called.
        $admin = fn (string $method): \Closure => fn (Request $r) => $this->admin()->{$method}($r);
        $router->post('/v1/admin/login', $admin('login'));
        $router->post('/v1/admin/logout', $admin('logout'));
        $router->get('/v1/admin/me', $admin('me'));
        $router->get('/v1/admin/queue', $admin('queue'));
        $router->get('/v1/admin/proposals', $admin('proposalsHistory'));
        $router->post('/v1/admin/intel/{id}/decision', $admin('decideIntel'));
        $router->post('/v1/admin/leaks/{id}/decision', $admin('decideLeak'));
        $router->post('/v1/admin/proposals/{id}/decision', $admin('decideProposal'));
        $router->get('/v1/admin/risks', $admin('risks'));
        $router->get('/v1/admin/risks/{code}', $admin('risk'));
        $router->add('PUT', '/v1/admin/risks/{code}', $admin('updateRisk'));
        $router->get('/v1/admin/sources', $admin('sources'));
        // Literal paths before {code}: the first matching route wins.
        $router->post('/v1/admin/sources/preview', $admin('previewSource'));
        $router->post('/v1/admin/sources/{code}', $admin('updateSource'));
        $router->post('/v1/admin/sources/{code}/probe', $admin('probeSource'));
        $router->post('/v1/admin/sources', $admin('createSource'));
        $router->add('PUT', '/v1/admin/sources/{code}', $admin('editSource'));
        $router->post('/v1/admin/sources/{code}/delete', $admin('deleteSource'));
        $router->post('/v1/admin/probe', $admin('probeUrl'));
        $router->get('/v1/admin/statistics', $admin('statistics'));
        $router->get('/v1/admin/alerts', $admin('alerts'));
        $router->post('/v1/admin/alerts', $admin('createAlert'));
        $router->add('PUT', '/v1/admin/alerts/{id}', $admin('editAlert'));
        $router->post('/v1/admin/alerts/{id}/close', $admin('closeAlert'));
        $router->get('/v1/admin/audit', $admin('audit'));

        return $router;
    }

    private function secret(): string
    {
        $secret = $this->config->require('APP_SECRET');
        if (strlen($secret) < 32) {
            throw new \RuntimeException('APP_SECRET must be at least 32 characters.');
        }

        return $secret;
    }

    private function admin(): AdminController
    {
        if ($this->admin === null) {
            $pdo = $this->db->connection(Database::WRITE);
            $secure = $this->config->get('COOKIE_SECURE') !== null
                ? $this->config->get('COOKIE_SECURE') === '1'
                : !$this->config->isDev();
            $this->admin = new AdminController(
                new AdminAuth($pdo, new RateLimiter($pdo, $this->secret()), $secure),
                new AdminRepository($pdo),
                $this->dbDir() . '/rules',
                new AlertRepository($pdo),
            );
        }

        return $this->admin;
    }

    /** Release package: db/ inside the application root. Repository: next to api/. */
    private function dbDir(): string
    {
        $appRoot = getenv('RS_APP_ROOT') ?: dirname(__DIR__);

        return is_dir($appRoot . '/db') ? $appRoot . '/db' : dirname($appRoot) . '/db';
    }

    private function setup(): SetupController
    {
        return new SetupController($this->config, $this->db, $this->dbDir());
    }

    private function proposals(): ProposalController
    {
        if ($this->proposals === null) {
            // Default: rs_read, whose column grants make "pending" the only
            // possible status. Fallback for hosting without fine-grained GRANT
            // (DB_PUBLIC_WRITES=write): rs_write, the INSERT never names the
            // status column, so the default "pending" still applies.
            $role = $this->config->get('DB_PUBLIC_WRITES', 'read') === 'write' ? Database::WRITE : Database::READ;
            $pdo = $this->db->connection($role);
            $this->proposals = new ProposalController($pdo, new RateLimiter($pdo, $this->secret()));
        }

        return $this->proposals;
    }

    public function handle(Request $request): Response
    {
        try {
            return $this->router->dispatch($request);
        } catch (ValidationException $e) {
            return Response::json([
                'error' => ['code' => 'validation', 'message' => 'Certains champs sont invalides.', 'fields' => $e->fields],
            ], 422);
        } catch (HttpException $e) {
            return Response::error($e->status, $e->errorCode, $e->getMessage());
        } catch (\Throwable $e) {
            // Never leak internals to the client: log, then answer generically.
            error_log(sprintf('[riskstudio] %s: %s in %s:%d', $e::class, $e->getMessage(), $e->getFile(), $e->getLine()));

            return Response::error(500, 'internal_error', 'An internal error occurred.');
        }
    }
}
