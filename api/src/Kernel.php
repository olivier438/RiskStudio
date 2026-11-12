<?php

declare(strict_types=1);

namespace RiskStudio;

use RiskStudio\Controller\PublicController;
use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;
use RiskStudio\Http\Router;

final class Kernel
{
    private readonly Router $router;

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

        return $router;
    }

    public function handle(Request $request): Response
    {
        try {
            return $this->router->dispatch($request);
        } catch (HttpException $e) {
            return Response::error($e->status, $e->errorCode, $e->getMessage());
        } catch (\Throwable $e) {
            // Never leak internals to the client: log, then answer generically.
            error_log(sprintf('[riskstudio] %s: %s in %s:%d', $e::class, $e->getMessage(), $e->getFile(), $e->getLine()));

            return Response::error(500, 'internal_error', 'An internal error occurred.');
        }
    }
}
