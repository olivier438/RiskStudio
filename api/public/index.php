<?php

/**
 * Risk Studio v5 API front controller.
 *
 * Dev:  php -S 127.0.0.1:8080 api/public/index.php   (see Makefile)
 * Prod: Apache rewrites /api/* here (see .htaccess). The application root,
 *       which holds src/, vendor/ and .env, lives outside the web root and is
 *       given by RS_APP_ROOT, or defaults to the parent of this folder.
 */

declare(strict_types=1);

$appRoot = getenv('RS_APP_ROOT') ?: dirname(__DIR__);

require $appRoot . '/vendor/autoload.php';

use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Http\Request;
use RiskStudio\Kernel;

$config = Config::fromFile($appRoot . '/.env');

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('expose_php', '0');
header_remove('X-Powered-By');

$kernel = new Kernel($config, new Database($config));
$kernel->handle(Request::fromGlobals((string) $config->get('API_BASE_PATH', '/api')))->send();
