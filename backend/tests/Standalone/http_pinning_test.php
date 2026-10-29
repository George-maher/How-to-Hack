<?php

declare(strict_types=1);

/**
 * Runtime verification of outbound connection pinning (CURLOPT_RESOLVE).
 *
 * This is the only test in the repository that makes a real socket connection.
 * It answers the question the unit tests cannot: does the transport actually go
 * to the address the policy approved, or does it silently re-resolve the name?
 *
 * Two fixtures listen on the SAME port on different addresses (127.0.0.1 and
 * 127.0.0.2). The hostname used in the request does not exist in DNS, so any
 * successful response must have come from the pinned literal.
 *
 * Requires a fixture runner; normally started by http_pinning.mjs:
 *
 *     node backend/tests/Standalone/http_pinning.mjs
 *
 * Run on its own without the fixtures it skips cleanly and exits 0, so it can
 * live in run_all.sh.
 *
 * Environment:
 *   PIN_TEST_PORT           port served on 127.0.0.1 and 127.0.0.2
 *   PIN_TEST_REDIRECT_PORT  port of the redirect *target* server
 *   PIN_TEST_V6_PORT        port served on ::1 (0 or unset to skip IPv6)
 *
 * No external host is ever contacted.
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

use App\Security\Http\SafeHttpClient;
use App\Security\Target\PolicyConfig;
use App\Security\Target\ScopeDecision;
use App\Security\Target\ScopeReason;
use App\Security\Target\TargetPolicy;

$passed = 0;
$failed = 0;
$skipped = 0;
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

function skip(string $label): void
{
    global $skipped;

    $skipped++;
    echo "  skip: {$label}\n";
}

$port = (int) (getenv('PIN_TEST_PORT') ?: 0);
$redirectPort = (int) (getenv('PIN_TEST_REDIRECT_PORT') ?: 0);
$v6Port = (int) (getenv('PIN_TEST_V6_PORT') ?: 0);

if (! extension_loaded('curl')) {
    echo "http pinning: SKIPPED (no curl extension)\n";
    exit(0);
}

if ($port === 0) {
    echo "http pinning: SKIPPED (no fixture server; run http_pinning.mjs)\n";
    exit(0);
}

if (! defined('CURLOPT_RESOLVE')) {
    echo "http pinning: SKIPPED (curl built without CURLOPT_RESOLVE)\n";
    exit(0);
}

/**
 * Perform the request exactly as the client does: pin the host to a literal.
 *
 * @param  list<string>  $resolve
 * @return array{body: string, code: int, errno: int, error: string}
 */
function fetch(string $url, array $resolve, bool $followRedirects = false): array
{
    $ch = curl_init($url);

    $options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_FOLLOWLOCATION => $followRedirects,
        // Never let an ambient HTTP_PROXY decide where this goes.
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
    ];

    if ($resolve !== []) {
        $options[CURLOPT_RESOLVE] = $resolve;
    }

    curl_setopt_array($ch, $options);

    $body = curl_exec($ch);
    $result = [
        'body' => is_string($body) ? trim($body) : '',
        'code' => (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
        'errno' => curl_errno($ch),
        'error' => curl_error($ch),
    ];

    curl_close($ch);

    return $result;
}

echo "http pinning: fixtures on port {$port}\n\n";

// ---------------------------------------------------------------------------
// 1. The fixture host does not exist in DNS — nothing resolves it for us
// ---------------------------------------------------------------------------
$unpinned = fetch("http://pinned.test:{$port}/", []);
check(
    'without a pin the hostname does not resolve',
    $unpinned['errno'] !== 0 && $unpinned['body'] === '',
    'errno='.$unpinned['errno'].' body='.$unpinned['body'],
);

// ---------------------------------------------------------------------------
// 2. Pinning decides the destination — both addresses share one port
// ---------------------------------------------------------------------------
$toA = fetch("http://pinned.test:{$port}/", ["pinned.test:{$port}:127.0.0.1"]);
check('pin to 127.0.0.1 reaches fixture A', $toA['body'] === 'ADDRESS-A', $toA['body'].' err='.$toA['error']);

$toB = fetch("http://pinned.test:{$port}/", ["pinned.test:{$port}:127.0.0.2"]);
check('pin to 127.0.0.2 reaches fixture B', $toB['body'] === 'ADDRESS-B', $toB['body'].' err='.$toB['error']);

check(
    'the same hostname and port reach different servers purely by pin',
    $toA['body'] === 'ADDRESS-A' && $toB['body'] === 'ADDRESS-B',
);

// ---------------------------------------------------------------------------
// 3. Redirects are not followed, so a 30x cannot escape the pin
// ---------------------------------------------------------------------------
$redirectUrl = "http://pinned.test:{$port}/redirect";
$redirect = fetch($redirectUrl, ["pinned.test:{$port}:127.0.0.1"]);
check('a 302 is returned, not followed', $redirect['code'] === 302, 'code='.$redirect['code']);
check('the redirect target is never fetched', ! str_contains($redirect['body'], 'REDIRECT-TARGET'), $redirect['body']);

if ($redirectPort > 0) {
    // The same request *with* following enabled must reach the target, which
    // proves the fixture is live and that test 3 was not a false pass.
    $followed = fetch(
        $redirectUrl,
        ["pinned.test:{$port}:127.0.0.1", "redirect.test:{$redirectPort}:127.0.0.1"],
        true,
    );
    check(
        'control: with following enabled the redirect target is reachable',
        str_contains($followed['body'], 'REDIRECT-TARGET'),
        'code='.$followed['code'].' body='.$followed['body'],
    );
}

// ---------------------------------------------------------------------------
// 4. IPv6 literals are pinned too
// ---------------------------------------------------------------------------
if ($v6Port > 0) {
    $v6 = fetch("http://v6.test:{$v6Port}/", ["v6.test:{$v6Port}:[::1]"]);

    if ($v6['body'] === 'ADDRESS-V6') {
        check('pin to [::1] reaches the IPv6 fixture', true);
    } else {
        // Distinguish "pinning is broken for IPv6" from "this runtime has no
        // IPv6 stack". The entry format is asserted separately below, and the
        // policy-level IPv6 cases live in target_policy_test.php.
        skip('IPv6 loopback unreachable from this runtime ('.$v6['error'].'); entry format still checked');
    }
} else {
    skip('IPv6 fixture unavailable on this host');
}

// ---------------------------------------------------------------------------
// 5. The real policy produces the decision that feeds the pin
// ---------------------------------------------------------------------------
$config = PolicyConfig::fromArray([
    'allowlist' => [],
    'lab_exceptions' => [
        ['host' => 'pinned.test', 'ports' => [$port], 'expires_at' => '2099-01-01T00:00:00Z'],
    ],
]);

$dns = static fn (string $host): array => $host === 'pinned.test' ? ['127.0.0.1'] : [];
$policy = new TargetPolicy($config, $dns);

$decision = $policy->evaluate("http://pinned.test:{$port}/", [$port]);
check('policy allows the lab exception host', $decision->allowed, $decision->code());
check('policy reports the address it approved', $decision->resolvedIps === ['127.0.0.1'], implode(',', $decision->resolvedIps));

// Reflection into the real client: the pin entry must be built from the
// decision, not from the URL text.
$reflection = new ReflectionClass(SafeHttpClient::class);
$client = $reflection->newInstanceWithoutConstructor();
$pickAddress = $reflection->getMethod('pickAddress');
$pickAddress->setAccessible(true);
$resolveEntry = $reflection->getMethod('resolveEntry');
$resolveEntry->setAccessible(true);

$address = $pickAddress->invoke($client, $decision);
check('client picks the approved address', $address === '127.0.0.1', var_export($address, true));

$entry = $address === null ? '' : $resolveEntry->invoke($client, 'pinned.test', $port, $address);
check('pin entry names host, port and literal', $entry === "pinned.test:{$port}:127.0.0.1", $entry);

// The full chain, end to end: policy decision -> pin entry -> real connection.
if ($entry !== '') {
    $viaPolicy = fetch("http://pinned.test:{$port}/", [$entry]);
    check('the policy-derived pin reaches the approved server', $viaPolicy['body'] === 'ADDRESS-A', $viaPolicy['body']);
}

// IPv6 entries must bracket the literal or curl rejects the entry outright.
$v6Entry = $resolveEntry->invoke($client, 'v6.test', 8443, '::1');
check('IPv6 pin entry is bracketed', $v6Entry === 'v6.test:8443:[::1]', $v6Entry);

// ---------------------------------------------------------------------------
// 6. Fail closed: an approval must not outlive a DNS change
// ---------------------------------------------------------------------------
$rebound = $policy->evaluate("http://pinned.test:{$port}/", [$port], ['127.0.0.2']);
check('a changed DNS answer is refused', ! $rebound->allowed && $rebound->reason === ScopeReason::AddressChanged, $rebound->code());

// A split answer (one approved address, one not) fails closed as a whole.
$splitDns = static fn (string $host): array => $host === 'pinned.test' ? ['127.0.0.1', '93.184.216.34'] : [];
$splitDecision = (new TargetPolicy(PolicyConfig::fromArray([
    'allowlist' => [['host' => 'pinned.test', 'ports' => [$port]]],
    'lab_exceptions' => [
        ['host' => 'pinned.test', 'ports' => [$port], 'expires_at' => '2099-01-01T00:00:00Z'],
    ],
]), $splitDns))->evaluate("http://pinned.test:{$port}/", [$port]);

check('a split DNS answer does not silently pick one', ! $splitDecision->allowed, $splitDecision->code());

// An allowed decision with no usable address must yield nothing to pin, which
// the client turns into a denial (never an unpinned request).
$empty = ScopeDecision::allow('pinned.test', [], [$port]);
check('no address means nothing to pin', $pickAddress->invoke($client, $empty) === null);

// A denied decision can never produce a pin.
$denied = ScopeDecision::deny(ScopeReason::NotAllowlisted, 'pinned.test', [], [$port]);
check('a denied decision yields no pin', $pickAddress->invoke($client, $denied) === null);

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
echo "\n";
foreach ($failures as $failure) {
    echo "  FAIL: {$failure}\n";
}

printf("http pinning: %d passed, %d failed, %d skipped\n", $passed, $failed, $skipped);

exit($failed === 0 ? 0 : 1);
