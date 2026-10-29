<?php

declare(strict_types=1);

/**
 * Standalone behavioural tests for the target policy.
 *
 * These require no framework, no database and no network: the resolver is
 * injected, so every DNS answer is deterministic. They run anywhere PHP 8.2 is
 * available:
 *
 *     php backend/tests/Standalone/target_policy_test.php
 *
 * Exit code 0 means every assertion passed.
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

use App\Security\Target\AllowlistRule;
use App\Security\Target\PolicyConfig;
use App\Security\Target\ScopeReason;
use App\Security\Target\TargetPolicy;

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

/**
 * Build a policy whose DNS answers are scripted.
 *
 * @param  array<string, list<string>>  $dns
 * @param  array<string, mixed>  $overrides
 */
function policy(array $dns, array $overrides = []): TargetPolicy
{
    $config = PolicyConfig::fromArray(array_merge([
        'allowlist' => [
            ['host' => 'app.example.com', 'ports' => [443]],
            ['host' => 'example.org'],
            ['host' => 'cdn.example.net', 'cidrs' => ['93.184.216.0/24']],
            ['host' => 'wild.example.com', 'include_subdomains' => true],
            ['host' => '93.184.216.34'],
            ['host' => 'wide.example.io', 'ports' => [80, 443]],
        ],
        'lab_exceptions' => [
            [
                'host' => '127.0.0.1',
                'ports' => [8080],
                'expires_at' => '2999-01-01T00:00:00Z',
                'note' => 'local lab',
            ],
            [
                'host' => 'lab.internal',
                'ports' => [443],
                'expires_at' => '2999-01-01T00:00:00Z',
            ],
            [
                'host' => '10.0.0.5',
                'ports' => [22],
                'expires_at' => '2000-01-01T00:00:00Z',
                'note' => 'expired on purpose',
            ],
        ],
    ], $overrides));

    return new TargetPolicy($config, static fn (string $host): array => $dns[$host] ?? []);
}

$dns = [
    'app.example.com' => ['93.184.216.34'],
    'example.org' => ['93.184.216.34'],
    'cdn.example.net' => ['93.184.216.34'],
    'wild.example.com' => ['93.184.216.34'],
    'sub.wild.example.com' => ['93.184.216.34'],
    'lab.internal' => ['10.0.0.5'],
    'split.example.com' => ['93.184.216.34', '127.0.0.1'],
    'private-name.example.com' => ['10.1.2.3'],
    '127.0.0.1.nip.io' => ['127.0.0.1'],
    'many.example.com' => [
        '93.184.216.1', '93.184.216.2', '93.184.216.3', '93.184.216.4',
        '93.184.216.5', '93.184.216.6', '93.184.216.7', '93.184.216.8',
        '93.184.216.9',
    ],
    'moving.example.com' => ['93.184.216.44'],
    'unlisted.example.com' => ['93.184.216.99'],
];

$policy = policy($dns);

// The same configuration with no lab exceptions: the default, deny-by-default
// world an operator starts in.
$strict = policy($dns, ['lab_exceptions' => []]);

// ---------------------------------------------------------------------------
// Allowlist behaviour
// ---------------------------------------------------------------------------
$d = $policy->evaluate('https://app.example.com/login');
check('allowlisted public host is allowed', $d->allowed && $d->reason === ScopeReason::Allowed, $d->code());
check('allowlisted host records matched rule', $d->matchedRule === 'security.allowlist[0]', (string) $d->matchedRule);
check('allowlisted host exposes resolved addresses', $d->resolvedIps === ['93.184.216.34'], implode(',', $d->resolvedIps));
check('default port derived from scheme', $d->ports === [443], implode(',', $d->ports));

$d = $policy->evaluate('http://example.org/');
check('port defaults to 80 for http', $d->ports === [80], implode(',', $d->ports));

$d = $strict->evaluate('https://unlisted.example.com/');
check('unlisted public host is refused', ! $d->allowed && $d->reason === ScopeReason::NotAllowlisted, $d->code());

$d = $policy->evaluate('https://app.example.com:8443/');
check('port outside the rule is refused', ! $d->allowed && $d->reason === ScopeReason::PortNotAllowed, $d->code());

$d = $policy->evaluate('https://sub.wild.example.com/');
check('subdomain allowed only with include_subdomains', $d->allowed, $d->code());

$d = $policy->evaluate('https://example.com/');
check('sibling domain is not matched by a subdomain rule', ! $d->allowed, $d->code());

$d = $policy->evaluate('https://cdn.example.net/asset.js');
check('allowlisted host within its CIDR is allowed', $d->allowed, $d->code());

$moved = policy(['cdn.example.net' => ['198.18.0.1']]);
$d = $moved->evaluate('https://cdn.example.net/asset.js');
check('host resolving outside its CIDR is refused', ! $d->allowed, $d->code());

$d = $policy->evaluate('https://93.184.216.34/');
check('IP literal in the allowlist is allowed', $d->allowed, $d->code());

$d = $policy->evaluate('https://1.1.1.1/');
check('unlisted public IP literal is refused', ! $d->allowed && $d->reason === ScopeReason::NotAllowlisted, $d->code());

// ---------------------------------------------------------------------------
// Non-public address classes
// ---------------------------------------------------------------------------
$cases = [
    'http://127.0.0.1/' => ScopeReason::Loopback,
    'http://127.10.20.30/' => ScopeReason::Loopback,
    'http://10.0.0.1/' => ScopeReason::PrivateAddress,
    'http://172.16.5.4/' => ScopeReason::PrivateAddress,
    'http://172.31.255.254/' => ScopeReason::PrivateAddress,
    'http://192.168.1.1/' => ScopeReason::PrivateAddress,
    'http://169.254.1.1/' => ScopeReason::LinkLocal,
    'http://169.254.169.254/latest/meta-data/' => ScopeReason::CloudMetadata,
    'http://100.64.0.1/' => ScopeReason::CarrierGradeNat,
    'http://224.0.0.1/' => ScopeReason::Multicast,
    'http://0.0.0.0/' => ScopeReason::Unspecified,
    'http://192.0.2.10/' => ScopeReason::Reserved,
    'http://255.255.255.255/' => ScopeReason::Reserved,
    'https://172.32.0.1/' => ScopeReason::NotAllowlisted, // just outside 172.16/12
];

foreach ($cases as $url => $expected) {
    $d = $strict->evaluate($url);
    check('address class for '.$url, ! $d->allowed && $d->reason === $expected, $d->code());
}

// ---------------------------------------------------------------------------
// Alternate IPv4 notations must not slip past the classifier
// ---------------------------------------------------------------------------
$alternates = [
    'http://2130706433/' => '127.0.0.1',
    'http://0x7f000001/' => '127.0.0.1',
    'http://0177.0.0.1/' => '127.0.0.1',
    'http://127.1/' => '127.0.0.1',
    'http://0x7f.1/' => '127.0.0.1',
    'http://127.0.1/' => '127.0.0.1',
];

foreach ($alternates as $url => $expectedHost) {
    $d = $strict->evaluate($url);
    check('alternate notation normalised: '.$url, $d->host === $expectedHost, $d->host);
    check('alternate notation refused: '.$url, ! $d->allowed && $d->reason === ScopeReason::Loopback, $d->code());
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------
$v6 = [
    'http://[::1]/' => ScopeReason::Loopback,
    'http://[::ffff:127.0.0.1]/' => ScopeReason::Loopback,
    'http://[::ffff:7f00:1]/' => ScopeReason::Loopback,
    'http://[64:ff9b::127.0.0.1]/' => ScopeReason::Loopback,
    'http://[fd00:ec2::254]/' => ScopeReason::CloudMetadata,
    'http://[fe80::1]/' => ScopeReason::LinkLocal,
    'http://[fc00::1]/' => ScopeReason::PrivateAddress,
    'http://[::]/' => ScopeReason::Unspecified,
    'http://[2001:db8::1]/' => ScopeReason::Reserved,
];

foreach ($v6 as $url => $expected) {
    $d = $strict->evaluate($url);
    check('ipv6 class for '.$url, ! $d->allowed && $d->reason === $expected, $d->code());
}

$d = $strict->evaluate('http://[fe80::1%25eth0]/');
check('ipv6 zone id is stripped before classification', $d->host === 'fe80::1', $d->host);

// ---------------------------------------------------------------------------
// Lab exceptions: scoped, expiring, never a network-wide pass
// ---------------------------------------------------------------------------
$d = $policy->evaluate('http://127.0.0.1:8080/');
check('loopback allowed by a scoped exception', $d->allowed && $d->reason === ScopeReason::AllowedByException, $d->code());

$d = $policy->evaluate('http://127.0.0.1:9090/');
check('exception does not cover other ports', ! $d->allowed && $d->reason === ScopeReason::PortNotAllowed, $d->code());

$d = $policy->evaluate('http://127.0.0.2:8080/');
check('exception does not cover other loopback addresses', ! $d->allowed, $d->code());

$d = $policy->evaluate('https://lab.internal/');
check('exception covers a private hostname', $d->allowed, $d->code());

$d = $strict->evaluate('https://10.0.0.9/');
check('exception does not widen to the whole private range', ! $d->allowed, $d->code());

$d = $policy->evaluate('http://10.0.0.5:22/');
check('expired exception is refused explicitly', ! $d->allowed && $d->reason === ScopeReason::LabExceptionExpired, $d->code());

$d = $policy->evaluate('http://169.254.169.254:8080/');
check('metadata endpoint is refused even with a matching exception', ! $d->allowed, $d->code());

$withMetadata = policy($dns, [
    'lab_exceptions' => [[
        'host' => '169.254.169.254',
        'ports' => [80],
        'expires_at' => '2999-01-01T00:00:00Z',
    ]],
]);
$d = $withMetadata->evaluate('http://169.254.169.254/');
check('metadata cannot be authorized by configuration', ! $d->allowed && $d->reason === ScopeReason::CloudMetadata, $d->code());

// ---------------------------------------------------------------------------
// DNS behaviour: unresolved, rebinding, split answers, fan-out
// ---------------------------------------------------------------------------
$d = $strict->evaluate('https://does-not-resolve.example/');
check('unresolved host is refused', ! $d->allowed && $d->reason === ScopeReason::Unresolved, $d->code());

$d = $strict->evaluate('https://moving.example.com/', [], ['93.184.216.45']);
check('changed address is refused when pinned', ! $d->allowed && $d->reason === ScopeReason::AddressChanged, $d->code());

$d = $strict->evaluate('https://moving.example.com/', [], ['93.184.216.44']);
check('unchanged pin is accepted', ! $d->allowed && $d->reason === ScopeReason::NotAllowlisted, $d->code());

$d = $strict->evaluate('http://split.example.com/');
check('split public/private answer is refused', ! $d->allowed && $d->reason === ScopeReason::AddressNotAllowed, $d->code());

$d = $strict->evaluate('http://127.0.0.1.nip.io/');
check('hostname resolving to loopback is refused', ! $d->allowed && $d->reason === ScopeReason::Loopback, $d->code());

$d = $strict->evaluate('https://many.example.com/');
check('too many addresses is refused', ! $d->allowed && $d->reason === ScopeReason::TooManyAddresses, $d->code());

// ---------------------------------------------------------------------------
// Input shape
// ---------------------------------------------------------------------------
$shape = [
    'not-a-url' => ScopeReason::InvalidUrl,
    'ftp://app.example.com/' => ScopeReason::UnsupportedScheme,
    'file:///etc/passwd' => ScopeReason::UnsupportedScheme,
    'https://user:pass@app.example.com/' => ScopeReason::InvalidUrl,
    'https://app example.com/' => ScopeReason::InvalidHost,
    'https://exämple.com/' => ScopeReason::InvalidHost,
    '' => ScopeReason::InvalidUrl,
];

foreach ($shape as $url => $expected) {
    $d = $strict->evaluate($url);
    check('input shape for "'.$url.'"', ! $d->allowed && $d->reason === $expected, $d->code());
}

// ---------------------------------------------------------------------------
// Configuration validation: a malformed rule fails at boot, never silently
// ---------------------------------------------------------------------------
$invalidConfigs = [
    'wildcard host' => [['host' => '*.example.com']],
    'cidr as host' => [['host' => '10.0.0.0/8']],
    'exception without ports' => [['host' => '127.0.0.1', 'expires_at' => '2999-01-01T00:00:00Z']],
    'exception without expiry' => [['host' => '127.0.0.1', 'ports' => [8080]]],
    'exception with cidr' => [[
        'host' => '127.0.0.1', 'ports' => [8080], 'expires_at' => '2999-01-01T00:00:00Z',
        'cidrs' => ['10.0.0.0/8'],
    ]],
];

foreach ($invalidConfigs as $label => $rules) {
    $threw = false;

    try {
        PolicyConfig::fromArray(['lab_exceptions' => $rules]);
    } catch (InvalidArgumentException) {
        $threw = true;
    }

    check('invalid exception config rejected: '.$label, $threw);
}

$threw = false;
try {
    new PolicyConfig(allowPrivateByDefault: true);
} catch (InvalidArgumentException) {
    $threw = true;
}
check('blanket private access is not configurable', $threw);

$threw = false;
try {
    AllowlistRule::fromConfig(['host' => 'example.com', 'ports' => [0]], 0, false);
} catch (InvalidArgumentException) {
    $threw = true;
}
check('out-of-range port in config is rejected', $threw);

$threw = false;
try {
    AllowlistRule::fromConfig(['host' => 'example.com', 'cidrs' => ['0.0.0.0/0']], 0, false);
} catch (InvalidArgumentException) {
    $threw = true;
}
check('over-broad CIDR in config is rejected', $threw);

// ---------------------------------------------------------------------------
// Decisions are explainable and serialisable
// ---------------------------------------------------------------------------
$d = $strict->evaluate('http://127.0.0.1/');
$serialised = $d->toArray();
check('denial serialises its reason', $serialised['reason'] === 'loopback');
check('denial carries an operator message', $d->message() !== '');
check('denial carries no matched rule', $serialised['matched_rule'] === null);
check('scope code matches reason', $d->code() === 'loopback');

$d = $policy->evaluate('https://app.example.com/');
check('allow serialises allowed=true', $d->toArray()['allowed'] === true);

// ---------------------------------------------------------------------------
printf("\nstandalone target-policy tests: %d passed, %d failed\n", $passed, $failed);

if ($failed > 0) {
    echo "\nFailures:\n - ".implode("\n - ", $failures)."\n";
    exit(1);
}

exit(0);
