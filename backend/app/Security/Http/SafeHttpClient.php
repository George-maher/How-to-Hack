<?php

declare(strict_types=1);

namespace App\Security\Http;

use App\Exceptions\TargetNotAuthorised;
use App\Services\Security\TargetScopeService;
use App\Security\Target\ScopeDecision;
use App\Security\Target\ScopeReason;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

/**
 * Outbound HTTP client for in-process (PHP) scanners.
 *
 * Enforced here, once, for every request a scanner makes:
 *  - the destination is re-evaluated against the target policy *before* each
 *    request (a scanner cannot walk to a discovered URL that is out of scope);
 *  - redirects are not followed automatically, so a 30x cannot smuggle the
 *    scanner to an unvalidated host;
 *  - the connection is pinned to the address that passed the policy
 *    (CURLOPT_RESOLVE), closing the resolve-then-connect rebinding window;
 *  - anything unexpected fails closed with a denial, never an open request.
 *
 * This is a secondary boundary. The primary one is the Runner, which evaluates
 * policy independently before starting a container.
 */
final class SafeHttpClient
{
    public function __construct(private readonly TargetScopeService $scope)
    {
    }

    /**
     * Guard a URL and return a client pinned to its validated address.
     *
     * @param  list<string>|null  $pinnedIps  addresses recorded at approval time
     *
     * @throws TargetNotAuthorised
     */
    public function for(string $url, int $timeoutSeconds = 15, ?array $pinnedIps = null): PendingRequest
    {
        [$host, $port] = $this->hostAndPort($url);

        $decision = $this->scope->evaluate($url, [$port], $pinnedIps);

        if (! $decision->allowed) {
            throw TargetNotAuthorised::fromDecision($decision);
        }

        $address = $this->pickAddress($decision);

        return Http::timeout(max(1, $timeoutSeconds))
            ->connectTimeout(5)
            // Never follow a redirect: the destination would not be revalidated.
            ->withOptions([
                'allow_redirects' => false,
                'curl' => $address !== null
                    ? [CURLOPT_RESOLVE => [$this->resolveEntry($host, $port, $address)]]
                    : [],
            ])
            ->withHeaders(['User-Agent' => 'HowToHack-Scanner/1.0']);
    }

    /**
     * A guarded client whose destination is validated at *send* time.
     *
     * Preferred over for() because the URL is only known when the request is
     * actually made (and may be assembled by the caller afterwards).
     *
     * Validation alone is not enough: between the policy check and the socket
     * connect, the same hostname would be resolved again, and a second answer
     * could point somewhere else (DNS rebinding). So the middleware also pins
     * the connection to the address it just approved — the transport is told to
     * use that literal and never re-resolve.
     */
    public function guarded(int $timeout = 15, ?array $pinnedIps = null): PendingRequest
    {
        return Http::timeout(max(1, $timeout))
            ->connectTimeout(5)
            ->withOptions(['allow_redirects' => false])
            ->withMiddleware(function (callable $handler) use ($pinnedIps) {
                return function ($request, array $options) use ($handler, $pinnedIps) {
                    $url = (string) $request->getUri();
                    [$host, $port] = $this->hostAndPort($url);

                    $decision = $this->scope->evaluate($url, [$port], $pinnedIps);
                    if (! $decision->allowed) {
                        // Fail closed: the request never leaves the process.
                        throw TargetNotAuthorised::fromDecision($decision);
                    }

                    $address = $this->pickAddress($decision);

                    if ($address === null) {
                        // An allowed decision must name an address we can pin.
                        throw TargetNotAuthorised::fromDecision(ScopeDecision::deny(
                            ScopeReason::PolicyError,
                            $host,
                            [],
                            [$port],
                            'The target policy approved the request without a usable address.',
                        ));
                    }

                    // Hard-off redirects at the transport layer as well as in
                    // the client options, and pin the approved address.
                    $options['allow_redirects'] = false;
                    $options['curl'] = array_merge(
                        is_array($options['curl'] ?? null) ? $options['curl'] : [],
                        [CURLOPT_RESOLVE => [$this->resolveEntry($host, $port, $address)]],
                    );

                    return $handler($request, $options);
                };
            })
            ->withHeaders(['User-Agent' => 'HowToHack-Scanner/1.0']);
    }

    /**
     * CURLOPT_RESOLVE entry: "host:port:address", with IPv6 addresses bracketed.
     */
    private function resolveEntry(string $host, int $port, string $address): string
    {
        $literal = str_contains($address, ':') ? '['.$address.']' : $address;

        return sprintf('%s:%d:%s', $host, $port, $literal);
    }

    public function get(string $url, int $timeout = 15): Response
    {
        return $this->for($url, $timeout)->get($url);
    }

    /**
     * Validate a URL discovered in scanner output before it is reported or
     * followed. Untrusted input: never assume it is in scope.
     */
    public function isInScope(string $url): bool
    {
        return $this->decisionFor($url)->allowed;
    }

    public function decisionFor(string $url): ScopeDecision
    {
        [, $port] = $this->hostAndPort($url);

        return $this->scope->evaluate($url, [$port]);
    }

    /**
     * @return array{0: string, 1: int}
     */
    private function hostAndPort(string $url): array
    {
        $parsed = parse_url($url);
        $scheme = strtolower((string) ($parsed['scheme'] ?? 'http'));
        $port = (int) ($parsed['port'] ?? ($scheme === 'https' ? 443 : 80));

        return [(string) ($parsed['host'] ?? ''), $port];
    }

    /**
     * Choose the address to pin. The policy has already proven every returned
     * address is acceptable for this target.
     */
    private function pickAddress(ScopeDecision $decision): ?string
    {
        foreach ($decision->resolvedIps as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                return $ip;
            }
        }

        return null;
    }
}
