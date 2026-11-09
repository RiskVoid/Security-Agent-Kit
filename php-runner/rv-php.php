<?php
// rv-php: the PHP profile's commands (RW-013). Input: the code at /src (read-only). Output: JSON files in /out.
//   lint     parse every PHP file with PHP's own parser (token_get_all with TOKEN_PARSE): nothing is executed.
//            Lists files this PHP version can't parse (unsupported syntax for the analysis tools too).
//   routes   copy the application to /tmp/app, give it a throwaway environment (no client secrets: array cache,
//            session and mail, in-memory SQLite, sync queue) and run `php artisan route:list --json`. This boots
//            the application's code (service providers, configuration): ./rvkit asks before running it. Needs the
//            application's vendor/ folder in the source (no network to install packages).

const SKIP = ['vendor', 'node_modules', '.git', 'storage', 'bootstrap/cache'];

function out(string $name, array $data): void
{
    file_put_contents("/out/$name", json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    fwrite(STDOUT, "wrote /out/$name\n");
}

function php_files(string $root): Generator
{
    $it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        function ($f) use ($root) {
            $rel = ltrim(substr($f->getPathname(), strlen($root)), '/');
            foreach (SKIP as $s) {
                if ($rel === $s || str_starts_with($rel, "$s/")) {
                    return false;
                }
            }
            return $f->isDir() || str_ends_with($f->getFilename(), '.php');
        }));
    foreach ($it as $f) {
        yield ltrim(substr($f->getPathname(), strlen($root)), '/');
    }
}

function lint(string $ts): int
{
    $errors = [];
    $n = 0;
    foreach (php_files('/src') as $rel) {
        $n++;
        $code = file_get_contents("/src/$rel");
        if (str_ends_with($rel, '.blade.php')) {
            continue;  // templates are compiled by Blade first; not PHP as written
        }
        try {
            token_get_all($code, TOKEN_PARSE);
        } catch (ParseError $e) {
            $errors[] = ['file' => $rel, 'line' => $e->getLine(), 'error' => $e->getMessage()];
        }
    }
    out("lint-$ts.json", ['php' => PHP_VERSION, 'files' => $n, 'unparsable' => $errors,
        'note' => 'Parsed with PHP ' . PHP_VERSION . "'s own parser, nothing executed. Files listed here are "
            . 'unsupported syntax for this PHP version; analysis tools will skip or misread them.']);
    fwrite(STDOUT, "$n PHP files, " . count($errors) . " unparsable\n");
    return 0;
}

function copy_tree(string $from, string $to): void
{
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($from, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST);
    foreach ($it as $f) {
        $dest = $to . substr($f->getPathname(), strlen($from));
        if ($f->isLink()) {
            continue;  // no links out of the copy
        }
        $f->isDir() ? @mkdir($dest, 0700, true) : copy($f->getPathname(), $dest);
    }
}

function routes(string $ts): int
{
    if (!is_file('/src/artisan')) {
        fwrite(STDERR, "no artisan file: not a Laravel application\n");
        return 1;
    }
    if (!is_file('/src/vendor/autoload.php')) {
        out("routes-$ts.json", ['error' => 'vendor/ is missing from the source and the profile has no network to '
            . 'install packages. Run composer install in your copy of the code (or ask the client for '
            . '`php artisan route:list --json`) and import the export instead.']);
        return 2;
    }
    @mkdir('/tmp/app', 0700, true);
    copy_tree('/src', '/tmp/app');
    foreach (['storage/framework/cache/data', 'storage/framework/sessions', 'storage/framework/views',
                 'storage/logs', 'bootstrap/cache'] as $d) {
        @mkdir("/tmp/app/$d", 0700, true);
    }
    foreach (glob('/tmp/app/bootstrap/cache/*.php') ?: [] as $f) {
        unlink($f);  // cached config or routes from the client's machine
    }
    $env = ['APP_NAME=rvkit-profile', 'APP_ENV=rvkit-profile', 'APP_DEBUG=false',
        'APP_KEY=base64:' . base64_encode(random_bytes(32)), 'APP_URL=http://localhost',
        'DB_CONNECTION=sqlite', 'DB_DATABASE=:memory:', 'CACHE_STORE=array', 'CACHE_DRIVER=array',
        'SESSION_DRIVER=array', 'QUEUE_CONNECTION=sync', 'MAIL_MAILER=array', 'BROADCAST_CONNECTION=null',
        'BROADCAST_DRIVER=null', 'FILESYSTEM_DISK=local', 'LOG_CHANNEL=stderr', 'TELESCOPE_ENABLED=false'];
    file_put_contents('/tmp/app/.env', implode("\n", $env) . "\n");  // replaces any .env from the source
    @unlink('/tmp/app/.env.production');
    $version = trim((string) shell_exec('cd /tmp/app && php artisan --version 2>&1'));
    $json = shell_exec('cd /tmp/app && php artisan route:list --json 2>/tmp/route-errors.txt');
    $routes = json_decode((string) $json, true);
    if (!is_array($routes)) {
        out("routes-$ts.json", ['error' => 'route:list failed', 'framework' => $version,
            'stderr' => substr((string) file_get_contents('/tmp/route-errors.txt'), 0, 4000)]);
        return 3;
    }
    file_put_contents("/out/routes-$ts.json", json_encode($routes, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    out("routes-$ts.meta.json", ['framework' => $version, 'php' => PHP_VERSION, 'routes' => count($routes),
        'environment' => 'throwaway copy, no network, generated .env (no client secrets)']);
    fwrite(STDOUT, count($routes) . " routes ($version)\n");
    return 0;
}

$cmd = $argv[1] ?? '';
$ts = gmdate('Ymd\THis');
exit(match ($cmd) {
    'lint' => lint($ts),
    'routes' => routes($ts),
    default => (function () {
        fwrite(STDERR, "usage: rv-php lint|routes\n");
        return 1;
    })(),
});
