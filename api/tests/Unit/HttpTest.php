<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RiskStudio\Config;
use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;
use RiskStudio\Http\Router;
use RiskStudio\Migrator;
use RiskStudio\Repository\RiskFilter;

final class HttpTest extends TestCase
{
    public function testRouterMatchesPlaceholders(): void
    {
        $router = new Router();
        $router->get('/v1/risks/{code}', static fn (Request $r) => Response::json($r->params));

        $response = $router->dispatch(new Request('GET', '/v1/risks/R-GOV-01'));

        self::assertSame(200, $response->status);
        self::assertSame('{"code":"R-GOV-01"}', $response->body);
    }

    public function testRouterRejectsUnsafePlaceholderValues(): void
    {
        $router = new Router();
        $router->get('/v1/risks/{code}', static fn () => Response::json([]));

        $this->expectException(HttpException::class);
        $router->dispatch(new Request('GET', "/v1/risks/R'1"));
    }

    public function testRouterAnswers405WithAllowHeader(): void
    {
        $router = new Router();
        $router->get('/v1/health', static fn () => Response::json([]));

        $response = $router->dispatch(new Request('POST', '/v1/health'));

        self::assertSame(405, $response->status);
        self::assertSame('GET', $response->headers['Allow']);
    }

    public function testHeadIsServedByGetRoutes(): void
    {
        $router = new Router();
        $router->get('/v1/health', static fn () => Response::json(['ok' => true]));

        self::assertSame(200, $router->dispatch(new Request('HEAD', '/v1/health'))->status);
    }

    public function testETagReturns304WhenUnchanged(): void
    {
        $first = Response::json(['a' => 1])->withETag(new Request('GET', '/'));
        $etag = $first->headers['ETag'];

        $second = Response::json(['a' => 1])->withETag(new Request('GET', '/', [], ['if-none-match' => $etag]));

        self::assertSame(304, $second->status);
        self::assertSame('', $second->body);
    }

    public function testJsonKeepsFrenchAccents(): void
    {
        self::assertSame('{"name":"Sécurité"}', Response::json(['name' => 'Sécurité'])->body);
    }

    public function testPathNormalisation(): void
    {
        self::assertSame('/v1/risks', Request::normalisePath('//v1///risks/'));
        self::assertSame('/', Request::normalisePath(''));
    }

    public function testConfigParsing(): void
    {
        $values = Config::parse("# comment\nDB_NAME=riskstudio\nQUOTED=\"a b\"\nlower=ignored\nEMPTY=\n");

        self::assertSame(['DB_NAME' => 'riskstudio', 'QUOTED' => 'a b', 'EMPTY' => ''], $values);
    }

    public function testRiskFilterValidation(): void
    {
        $filter = RiskFilter::fromRequest(new Request('GET', '/', [
            'q' => ' ransomware ', 'env' => 'ot', 'category' => 'iam', 'impact_min' => '9', 'per_page' => '1000',
        ]));

        self::assertSame('ransomware', $filter->search);
        self::assertSame('OT', $filter->environment);
        self::assertSame('IAM', $filter->category);
        self::assertSame(5, $filter->impactMin);
        self::assertSame(200, $filter->perPage);
    }

    public function testRiskFilterRejectsInvalidCodes(): void
    {
        $this->expectException(HttpException::class);
        RiskFilter::fromRequest(new Request('GET', '/', ['category' => "IAM' OR 1=1"]));
    }

    public function testSqlSplitterIgnoresComments(): void
    {
        $sql = "-- header; with semicolon\nCREATE TABLE a (x INT);\n\nINSERT INTO a VALUES (1);\n";

        self::assertSame(['CREATE TABLE a (x INT)', 'INSERT INTO a VALUES (1)'], Migrator::splitStatements($sql));
    }
}
