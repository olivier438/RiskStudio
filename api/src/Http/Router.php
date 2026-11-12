<?php

declare(strict_types=1);

namespace RiskStudio\Http;

/**
 * Tiny router: exact segments and `{name}` placeholders, nothing else.
 * Placeholders only match [A-Za-z0-9_.-]+ so a route parameter can never carry
 * a slash, a quote or any other surprise.
 */
final class Router
{
    /** @var list<array{method: string, regex: string, names: list<string>, handler: callable}> */
    private array $routes = [];

    public function get(string $pattern, callable $handler): void
    {
        $this->add('GET', $pattern, $handler);
    }

    public function post(string $pattern, callable $handler): void
    {
        $this->add('POST', $pattern, $handler);
    }

    public function add(string $method, string $pattern, callable $handler): void
    {
        $names = [];
        $regex = preg_replace_callback(
            '/\\\\\{([a-z][a-zA-Z0-9_]*)\\\\\}/',
            static function (array $m) use (&$names): string {
                $names[] = $m[1];

                return '([A-Za-z0-9_.-]+)';
            },
            preg_quote(Request::normalisePath($pattern), '#'),
        );

        $this->routes[] = [
            'method' => strtoupper($method),
            'regex' => '#^' . $regex . '$#',
            'names' => $names,
            'handler' => $handler,
        ];
    }

    public function dispatch(Request $request): Response
    {
        $allowed = [];
        foreach ($this->routes as $route) {
            if (!preg_match($route['regex'], $request->path, $matches)) {
                continue;
            }
            $method = $request->method === 'HEAD' ? 'GET' : $request->method;
            if ($route['method'] !== $method) {
                $allowed[] = $route['method'];
                continue;
            }
            $params = array_combine($route['names'], array_slice($matches, 1)) ?: [];

            return ($route['handler'])($request->withParams($params));
        }

        if ($allowed !== []) {
            return Response::error(405, 'method_not_allowed', 'Method not allowed.')
                ->withHeader('Allow', implode(', ', array_unique($allowed)));
        }

        throw HttpException::notFound('Unknown endpoint.');
    }
}
