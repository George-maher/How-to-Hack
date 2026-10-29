<?php

declare(strict_types=1);

namespace App\Security\Target;

use Closure;
use Throwable;

/**
 * The single authorization decision for "may this instance touch this target".
 *
 * It is used at three boundaries, with the same inputs and the same rules:
 *   1. the API, before a scan is created;
 *   2. the queue worker, before each scanner runs;
 *   3. the Runner, immediately before a container is started.
 *
 * Properties:
 *  - deny by default: an unlisted public host is refused; nothing is scannable
 *    until an operator lists it;
 *  - private, loopback, link-local, CGNAT, multicast and reserved addresses are
 *    refused unless an unexpired, port-scoped lab exception names that exact
 *    host;
 *  - cloud metadata endpoints are refused unconditionally;
 *  - every address a name resolves to must be acceptable — a "split" answer
 *    (one public, one private) is refused rather than half-trusted;
 *  - anything unexpected becomes `policy_error`, which is a denial.
 */
final class TargetPolicy
{
    public function __construct(
        private readonly PolicyConfig $config,
        private readonly HostResolver|Closure|null $resolver = null,
    ) {
    }

    /**
     * @param  list<int>  $ports  ports the caller intends to touch; empty means
     *                            "the ports implied by the URL"
     * @param  list<string>|null  $pinnedIps  addresses recorded when the target
     *                                        was approved; when present, a change
     *                                        is a hard failure (rebinding defence)
     */
    public function evaluate(string $targetUrl, array $ports = [], ?array $pinnedIps = null): ScopeDecision
    {
        try {
            return $this->decide($targetUrl, $ports, $pinnedIps);
        } catch (Throwable $e) {
            // Fail closed. The message is for the operator; the reason is
            // intentionally generic.
            return ScopeDecision::deny(ScopeReason::PolicyError, detail: 'Policy evaluation error: '.$e->getMessage());
        }
    }

    public function config(): PolicyConfig
    {
        return $this->config;
    }

    /**
     * Convenience for scanners that only need a boolean plus a reason to throw.
     *
     * @param  list<int>  $ports
     */
    public function isAllowed(string $targetUrl, array $ports = [], ?array $pinnedIps = null): bool
    {
        return $this->evaluate($targetUrl, $ports, $pinnedIps)->allowed;
    }

    /**
     * @param  list<int>  $ports
     * @param  list<string>|null  $pinnedIps
     */
    private function decide(string $targetUrl, array $ports, ?array $pinnedIps): ScopeDecision
    {
        $parsed = @parse_url(trim($targetUrl));

        if (! is_array($parsed) || ! isset($parsed['scheme'])) {
            return ScopeDecision::deny(ScopeReason::InvalidUrl, detail: 'The target must be an absolute http(s) URL with a host.');
        }

        $scheme = strtolower((string) $parsed['scheme']);

        if (! in_array($scheme, ['http', 'https'], true)) {
            return ScopeDecision::deny(ScopeReason::UnsupportedScheme);
        }

        if (! isset($parsed['host']) || $parsed['host'] === '') {
            return ScopeDecision::deny(ScopeReason::InvalidUrl, detail: 'The target must include a host.');
        }

        // `https://user:pass@host/` is ambiguous across resolvers and proxies.
        if (isset($parsed['user']) || isset($parsed['pass'])) {
            return ScopeDecision::deny(ScopeReason::InvalidUrl, detail: 'Credentials in the URL are not accepted.');
        }

        $host = HostNormalizer::normalize((string) $parsed['host']);

        if ($host === null) {
            return ScopeDecision::deny(ScopeReason::InvalidHost, (string) $parsed['host']);
        }

        $requestedPorts = $this->normalizePorts($parsed, $scheme, $ports);

        if ($requestedPorts === null) {
            return ScopeDecision::deny(ScopeReason::PortNotAllowed, $host, [], [], 'The requested port is outside 1-65535.');
        }

        // ---- resolve -----------------------------------------------------
        $isLiteral = IpClassifier::isIpLiteral($host);
        $addresses = $isLiteral ? [$host] : $this->resolve($host);

        if ($addresses === []) {
            return ScopeDecision::deny(ScopeReason::Unresolved, $host, [], $requestedPorts);
        }

        if (count($addresses) > $this->config->maxResolvedAddresses) {
            return ScopeDecision::deny(ScopeReason::TooManyAddresses, $host, $addresses, $requestedPorts);
        }

        // ---- DNS pinning -------------------------------------------------
        if ($pinnedIps !== null && $pinnedIps !== []) {
            $pinned = array_values(array_unique(array_filter(array_map(
                static fn ($ip) => IpClassifier::normalize((string) $ip),
                $pinnedIps,
            ))));

            foreach ($pinned as $address) {
                if (! in_array($address, $addresses, true)) {
                    return ScopeDecision::deny(
                        ScopeReason::AddressChanged,
                        $host,
                        $addresses,
                        $requestedPorts,
                        'The target no longer resolves to the address that was approved.',
                    );
                }
            }
        }

        // ---- classify ----------------------------------------------------
        $nonPublic = [];
        foreach ($addresses as $address) {
            $class = (new IpClassifier())->classify($address);

            if ($class->isNeverPermittable()) {
                return ScopeDecision::deny($class->reason(), $host, $addresses, $requestedPorts);
            }

            if (! $class->isPublic()) {
                $nonPublic[$address] = $class;
            }
        }

        // ---- private / local targets -------------------------------------
        if ($nonPublic !== []) {
            if (count($nonPublic) !== count($addresses)) {
                // Some addresses are public and some are not: a classic
                // split-answer / rebinding shape. Refuse the whole target.
                return ScopeDecision::deny(
                    ScopeReason::AddressNotAllowed,
                    $host,
                    $addresses,
                    $requestedPorts,
                    'The target resolves to a mix of public and non-public addresses.',
                );
            }

            $match = $this->matchLabException($host, $requestedPorts, $addresses);

            if ($match['rule'] !== null) {
                return ScopeDecision::allow(
                    $host,
                    $addresses,
                    $requestedPorts,
                    ScopeReason::AllowedByException,
                    $match['rule']->id,
                );
            }

            if ($match['expired'] !== null) {
                return ScopeDecision::deny(ScopeReason::LabExceptionExpired, $host, $addresses, $requestedPorts);
            }

            // An exception exists for this host, but not for this port: say so
            // rather than reporting the address class, which would send the
            // operator looking in the wrong place.
            if ($match['port_mismatch']) {
                return ScopeDecision::deny(ScopeReason::PortNotAllowed, $host, $addresses, $requestedPorts);
            }

            $first = reset($nonPublic);

            return ScopeDecision::deny($first->reason(), $host, $addresses, $requestedPorts);
        }

        // ---- public targets: must be allowlisted --------------------------
        $match = $this->matchAllowlist($host, $requestedPorts, $addresses);

        if ($match['rule'] !== null) {
            return ScopeDecision::allow($host, $addresses, $requestedPorts, ScopeReason::Allowed, $match['rule']->id);
        }

        if ($match['port_mismatch']) {
            return ScopeDecision::deny(ScopeReason::PortNotAllowed, $host, $addresses, $requestedPorts);
        }

        if ($match['address_mismatch']) {
            return ScopeDecision::deny(ScopeReason::AddressNotAllowed, $host, $addresses, $requestedPorts);
        }

        return ScopeDecision::deny(ScopeReason::NotAllowlisted, $host, $addresses, $requestedPorts);
    }

    /**
     * @param  array<string, mixed>  $parsed
     * @param  list<int>  $ports
     * @return list<int>|null
     */
    private function normalizePorts(array $parsed, string $scheme, array $ports): ?array
    {
        $requested = [];

        foreach ($ports as $port) {
            if (! is_int($port) && ! (is_string($port) && ctype_digit($port))) {
                return null;
            }

            $value = (int) $port;
            if ($value < 1 || $value > 65535) {
                return null;
            }

            $requested[] = $value;
        }

        if ($requested === []) {
            $requested[] = isset($parsed['port'])
                ? (int) $parsed['port']
                : ($scheme === 'https' ? 443 : 80);
        }

        $requested = array_values(array_unique($requested));
        sort($requested);

        return $requested;
    }

    /**
     * @return list<string>
     */
    private function resolve(string $host): array
    {
        $answers = match (true) {
            $this->resolver instanceof HostResolver => $this->resolver->resolve($host),
            $this->resolver instanceof Closure => ($this->resolver)($host),
            default => (new SystemHostResolver())->resolve($host),
        };

        $addresses = [];
        foreach (is_array($answers) ? $answers : [] as $address) {
            $normalized = IpClassifier::normalize((string) $address);
            if ($normalized !== null) {
                $addresses[$normalized] = true;
            }
        }

        return array_keys($addresses);
    }

    /**
     * @param  list<int>  $ports
     * @param  list<string>  $addresses
     * @return array{rule: ?AllowlistRule, expired: ?AllowlistRule, port_mismatch: bool}
     */
    private function matchLabException(string $host, array $ports, array $addresses): array
    {
        $expired = null;
        $portMismatch = false;

        foreach ($this->config->labExceptions as $rule) {
            if (! $rule->matchesHost($host)) {
                continue;
            }

            if ($rule->isExpired()) {
                $expired = $rule;

                continue;
            }

            if (! $rule->allowsPorts($ports)) {
                $portMismatch = true;

                continue;
            }

            // Defence in depth: an exception names one host, so every address
            // it resolves to must belong to that host's own scope.
            if (! $rule->coversAddress($addresses[0] ?? '')) {
                continue;
            }

            return ['rule' => $rule, 'expired' => null, 'port_mismatch' => false];
        }

        return ['rule' => null, 'expired' => $expired, 'port_mismatch' => $portMismatch];
    }

    /**
     * @param  list<int>  $ports
     * @param  list<string>  $addresses
     * @return array{rule: ?AllowlistRule, port_mismatch: bool, address_mismatch: bool}
     */
    private function matchAllowlist(string $host, array $ports, array $addresses): array
    {
        $portMismatch = false;
        $addressMismatch = false;

        foreach ($this->config->allowlist as $rule) {
            if (! $rule->matchesHost($host)) {
                continue;
            }

            if (! $rule->allowsPorts($ports)) {
                $portMismatch = true;

                continue;
            }

            $addressOk = true;
            foreach ($addresses as $address) {
                if (! $rule->coversAddress($address)) {
                    $addressOk = false;
                    break;
                }
            }

            if (! $addressOk) {
                $addressMismatch = true;

                continue;
            }

            return ['rule' => $rule, 'port_mismatch' => false, 'address_mismatch' => false];
        }

        return ['rule' => null, 'port_mismatch' => $portMismatch, 'address_mismatch' => $addressMismatch];
    }
}
