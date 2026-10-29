<?php

declare(strict_types=1);

/**
 * Standalone tests for the API <-> Runner boundary.
 *
 * These run without Laravel, a database or a network, because the contract
 * itself is pure: what identifier the API generates, and whether it satisfies
 * the schema the Runner enforces.
 *
 *     php backend/tests/Standalone/runner_contract_test.php
 */

$root = dirname(__DIR__, 2);

spl_autoload_register(static function (string $class) use ($root): void {
    if (! str_starts_with($class, 'App\\')) {
        return;
    }

    $path = $root.'/app/'.str_replace('\\', '/', substr($class, 4)).'.php';

    if (is_file($path)) {
        require_once $path;
    }
});

use App\Security\Scan\JobId;
use App\Security\Target\TargetUrl;

$passed = 0;
$failed = 0;
$failures = [];

function check(string $label, bool $condition, string $context = ''): void
{
    global $passed, $failed, $failures;

    if ($condition) {
        $passed++;

        return;
    }

    $failed++;
    $failures[] = $label.($context !== '' ? ' — '.$context : '');
}

// ---------------------------------------------------------------------------
// The identifier the Runner validates (runner/src/validate.mjs
// JOB_ID_PATTERN = /^[A-Za-z0-9_-]{8,64}$/)
// ---------------------------------------------------------------------------

$id = JobId::for(1, 'nmap', 'fingerprint-abc');

check('job id matches the Runner schema', (bool) preg_match('/^[A-Za-z0-9_-]{8,64}$/', $id), $id);
check('job id is at least 8 characters', strlen($id) >= 8, $id);
check('job id is at most 64 characters', strlen($id) <= 64, $id);
check('job id is reported valid by the shared validator', JobId::isValid($id), $id);
check('job id embeds the scan id', str_starts_with($id, 's1-'), $id);
check('job id embeds the tool', str_contains($id, 'nmap'), $id);

// ---------------------------------------------------------------------------
// Stability: the idempotency guarantee
// ---------------------------------------------------------------------------
check('the same inputs produce the same id', JobId::for(7, 'nuclei', 'fp') === JobId::for(7, 'nuclei', 'fp'));
check('a different scan produces a different id', JobId::for(7, 'nuclei', 'fp') !== JobId::for(8, 'nuclei', 'fp'));
check('a different tool produces a different id', JobId::for(7, 'nuclei', 'fp') !== JobId::for(7, 'nikto', 'fp'));
check(
    'a changed plan produces a different id (no stale replay)',
    JobId::for(7, 'nuclei', 'fp-a') !== JobId::for(7, 'nuclei', 'fp-b'),
);
check(
    'a missing fingerprint is handled without error',
    JobId::isValid(JobId::for(7, 'nuclei', null)),
);

// ---------------------------------------------------------------------------
// Hostile inputs must still produce a valid, safe id
// ---------------------------------------------------------------------------
$hostileTools = [
    'nmap; rm -rf /',
    'nmap && curl evil',
    '../../etc/passwd',
    'nm ap',
    '工具',
    '',
    str_repeat('a', 500),
];

foreach ($hostileTools as $tool) {
    $generated = JobId::for(3, $tool, 'fp');

    check('hostile tool name yields a valid id: '.mb_substr($tool, 0, 20), JobId::isValid($generated), $generated);
    check(
        'hostile tool name leaves no shell metacharacter: '.mb_substr($tool, 0, 20),
        (bool) preg_match('/^[A-Za-z0-9_-]+$/', $generated),
        $generated,
    );
}

$hugeId = JobId::for(999999999999, str_repeat('x', 200), str_repeat('f', 200));
check('a pathological scan id is truncated to the limit', strlen($hugeId) <= 64, (string) strlen($hugeId));
check('a truncated id is still valid', JobId::isValid($hugeId), $hugeId);

// ---------------------------------------------------------------------------
// The validator must reject what the Runner rejects
// ---------------------------------------------------------------------------
$invalid = [
    '',
    'short',
    'has space here',
    'has/slash',
    'has.dot',
    'a' . str_repeat('b', 64),
    "with\nnewline",
];

foreach ($invalid as $candidate) {
    check('validator rejects: "'.addcslashes($candidate, "\n").'"', ! JobId::isValid($candidate));
}

// ---------------------------------------------------------------------------
// The URL the API sends must agree with the host the policy approved
// (runner/src/validate.mjs rejects a mismatch)
// ---------------------------------------------------------------------------
$urlCases = [
    // original, approved host, scheme, port, expected
    ['https://app.example.com/login', 'app.example.com', 'https', 443, 'https://app.example.com/login'],
    ['https://APP.example.com/login', 'app.example.com', 'https', 443, 'https://app.example.com/login'],
    ['http://2130706433:8080/', '127.0.0.1', 'http', 8080, 'http://127.0.0.1:8080/'],
    ['https://app.example.com:8443/a/b?x=1', 'app.example.com', 'https', 8443, 'https://app.example.com:8443/a/b?x=1'],
    ['http://[::1]:9000/x', '::1', 'http', 9000, 'http://[::1]:9000/x'],
    ['https://app.example.com', 'app.example.com', 'https', 443, 'https://app.example.com/'],
];

foreach ($urlCases as [$original, $host, $scheme, $port, $expected]) {
    $rebuilt = TargetUrl::rebuild($original, $host, $scheme, $port);
    check('URL rebuilt for '.$original, $rebuilt === $expected, $rebuilt);

    $parsedHost = parse_url($rebuilt, PHP_URL_HOST);
    $parsedHost = is_string($parsedHost) ? trim($parsedHost, '[]') : '';

    check('rebuilt URL host matches the approved host for '.$original, $parsedHost === $host, (string) $parsedHost);
}

// The rebuilt URL must never carry credentials, whatever the original did.
$rebuilt = TargetUrl::rebuild('https://user:pass@app.example.com/x', 'app.example.com', 'https', 443);
check('rebuilt URL carries no credentials', ! str_contains($rebuilt, '@'), $rebuilt);
check('rebuilt URL keeps the path when credentials are stripped', str_contains($rebuilt, '/x'), $rebuilt);

// A path that does not start with "/" must not be able to alter the authority.
$rebuilt = TargetUrl::rebuild('https://app.example.com', 'app.example.com', 'https', 443);
check('rebuilt URL is absolute with a path', $rebuilt === 'https://app.example.com/', $rebuilt);

// An unknown scheme degrades to https rather than producing a dangerous scheme.
$rebuilt = TargetUrl::rebuild('gopher://app.example.com/x', 'app.example.com', 'gopher', 443);
check('unknown scheme falls back to https', str_starts_with($rebuilt, 'https://'), $rebuilt);

// ---------------------------------------------------------------------------
// Cross-check against the JavaScript pattern
// ---------------------------------------------------------------------------
$validateSource = @file_get_contents($root.'/../runner/src/validate.mjs');
if (is_string($validateSource) && $validateSource !== '') {
    check(
        'the JS and PHP id patterns are the same',
        str_contains($validateSource, '[A-Za-z0-9_-]{8,64}'),
    );
}

printf("\nstandalone runner-contract tests: %d passed, %d failed\n", $passed, $failed);

if ($failed > 0) {
    echo "\nFailures:\n - ".implode("\n - ", $failures)."\n";
    exit(1);
}

exit(0);
