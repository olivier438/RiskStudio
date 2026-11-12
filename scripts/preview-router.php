<?php

/**
 * Local stand-in for Apache on the shared hosting: serves web/build as static
 * files and sends /api/* to the PHP front controller. Dev and CI only.
 *
 *   php -S 127.0.0.1:8090 scripts/preview-router.php
 */

declare(strict_types=1);

$root = dirname(__DIR__);
$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($path === '/api' || str_starts_with($path, '/api/')) {
    require $root . '/api/public/index.php';
    return true;
}

$build = realpath($root . '/web/build');
$file = realpath($build . $path);
if ($file !== false && is_dir($file)) {
    $file = realpath($file . '/index.html');
}
if ($file === false || !str_starts_with($file, $build . DIRECTORY_SEPARATOR) || !is_file($file)) {
    http_response_code(404);
    echo 'Not found';
    return true;
}

$types = [
    'html' => 'text/html; charset=utf-8', 'js' => 'text/javascript', 'css' => 'text/css',
    'json' => 'application/json', 'svg' => 'image/svg+xml', 'jpg' => 'image/jpeg', 'png' => 'image/png',
    'txt' => 'text/plain', 'woff2' => 'font/woff2',
];
header('Content-Type: ' . ($types[pathinfo($file, PATHINFO_EXTENSION)] ?? 'application/octet-stream'));
header("Content-Security-Policy: frame-ancestors 'none'; object-src 'none'; base-uri 'self'");
header('X-Content-Type-Options: nosniff');
readfile($file);
return true;
