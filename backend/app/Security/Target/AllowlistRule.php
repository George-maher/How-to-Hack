<?php

declare(strict_types=1);

namespace App\Security\Target;

use InvalidArgumentException;

/**
 * One operator-authored rule.
 *
 * Two flavours share this shape:
 *  - an **allowlist** entry: a public host (or CIDR) this instance may scan;
 *  - a **lab exception**: a narrowly scoped, expiring authorisation for a
 *    local/private target. Exceptions must name one exact host and an explicit
 *    port list — they can never cover a whole private network.
 */
final class AllowlistRule
{
    /**
     * @param  list<int>  $ports  ports this rule covers (empty = any port)
     * @param  list<string>  $cidrs  optional address restriction (allowlist only)
     */
    public function __construct(
        public readonly string $id,
        public readonly string $host,
        public readonly array $ports = [],
        public readonly array $cidrs = [],
        public readonly ?\DateTimeImmutable $expiresAt = null,
        public readonly bool $includeSubdomains = false,
        public readonly bool $isLabException = false,
        public readonly string $note = '',
    ) {
    }

    /**
     * @param  array<string, mixed>|string  $entry
     */
    public static function fromConfig(string|array $entry, int $index, bool $isLabException): self
    {
        $label = $isLabException ? 'security.lab_exceptions' : 'security.allowlist';

        if (is_string($entry)) {
            if ($isLabException) {
                throw new InvalidArgumentException(
                    "{$label}[{$index}] must be an object: a lab exception needs explicit ports and an expiry.",
                );
            }

            $entry = ['host' => $entry];
        }

        $host = $entry['host'] ?? null;
        if (! is_string($host) || trim($host) === '') {
            throw new InvalidArgumentException("{$label}[{$index}] is missing a host.");
        }

        $host = trim($host);

        if (str_contains($host, '*')) {
            throw new InvalidArgumentException(
                "{$label}[{$index}] may not use wildcards; list each host explicitly.",
            );
        }

        if (str_contains($host, '/')) {
            throw new InvalidArgumentException(
                "{$label}[{$index}] may not be a CIDR range as a host; use the `cidrs` key to restrict addresses.",
            );
        }

        $normalized = HostNormalizer::normalize($host);
        if ($normalized === null) {
            throw new InvalidArgumentException("{$label}[{$index}] has an invalid host: {$host}");
        }

        $ports = self::parsePorts($entry['ports'] ?? [], $label, $index);

        if ($isLabException && $ports === []) {
            throw new InvalidArgumentException(
                "{$label}[{$index}] must list explicit ports; an exception may not cover every port.",
            );
        }

        $cidrs = self::parseCidrs($entry['cidrs'] ?? [], $label, $index);

        if ($isLabException && $cidrs !== []) {
            throw new InvalidArgumentException(
                "{$label}[{$index}] may not use CIDRs; a lab exception covers one exact host.",
            );
        }

        $expiresAt = null;

        if ($isLabException) {
            $raw = $entry['expires_at'] ?? null;
            if (! is_string($raw) || $raw === '') {
                throw new InvalidArgumentException(
                    "{$label}[{$index}] must set `expires_at`: a lab exception cannot be permanent.",
                );
            }

            try {
                $expiresAt = new \DateTimeImmutable($raw);
            } catch (\Exception) {
                throw new InvalidArgumentException("{$label}[{$index}] has an unparseable `expires_at`: {$raw}");
            }
        }

        return new self(
            id: is_string($entry['id'] ?? null) ? $entry['id'] : $label.'['.$index.']',
            host: $normalized,
            ports: $ports,
            cidrs: $cidrs,
            expiresAt: $expiresAt,
            includeSubdomains: (bool) ($entry['include_subdomains'] ?? false),
            isLabException: $isLabException,
            note: is_string($entry['note'] ?? null) ? $entry['note'] : '',
        );
    }

    public function matchesHost(string $host): bool
    {
        if ($this->host === $host) {
            return true;
        }

        if (! $this->includeSubdomains || IpClassifier::isIpLiteral($host)) {
            return false;
        }

        return str_ends_with($host, '.'.$this->host);
    }

    public function allowsPort(int $port): bool
    {
        return $this->ports === [] || in_array($port, $this->ports, true);
    }

    /**
     * @param  list<int>  $ports
     */
    public function allowsPorts(array $ports): bool
    {
        foreach ($ports as $port) {
            if (! $this->allowsPort($port)) {
                return false;
            }
        }

        return true;
    }

    public function coversAddress(string $ip): bool
    {
        if ($this->cidrs === []) {
            return true;
        }

        $normalized = IpClassifier::normalize($ip);
        if ($normalized === null) {
            return false;
        }

        $packed = inet_pton($normalized);
        if ($packed === false) {
            return false;
        }

        foreach ($this->cidrs as $cidr) {
            if (IpClassifier::inCidr($packed, $cidr)) {
                return true;
            }
        }

        return false;
    }

    public function isExpired(?\DateTimeImmutable $now = null): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return $this->expiresAt <= ($now ?? new \DateTimeImmutable());
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'host' => $this->host,
            'ports' => $this->ports,
            'cidrs' => $this->cidrs,
            'expires_at' => $this->expiresAt?->format(\DateTimeInterface::ATOM),
            'include_subdomains' => $this->includeSubdomains,
            'scope' => $this->isLabException ? 'lab_exception' : 'allowlist',
            'note' => $this->note,
        ];
    }

    /**
     * @return list<int>
     */
    private static function parsePorts(mixed $raw, string $label, int $index): array
    {
        if ($raw === null) {
            return [];
        }

        if (! is_array($raw)) {
            throw new InvalidArgumentException("{$label}[{$index}] `ports` must be a list of integers.");
        }

        $ports = [];

        foreach ($raw as $port) {
            if (! is_int($port) && ! (is_string($port) && ctype_digit($port))) {
                throw new InvalidArgumentException("{$label}[{$index}] has a non-numeric port.");
            }

            $value = (int) $port;

            if ($value < 1 || $value > 65535) {
                throw new InvalidArgumentException("{$label}[{$index}] has an out-of-range port: {$value}");
            }

            $ports[] = $value;
        }

        $ports = array_values(array_unique($ports));
        sort($ports);

        return $ports;
    }

    /**
     * @return list<string>
     */
    private static function parseCidrs(mixed $raw, string $label, int $index): array
    {
        if ($raw === null) {
            return [];
        }

        if (! is_array($raw)) {
            throw new InvalidArgumentException("{$label}[{$index}] `cidrs` must be a list of CIDR strings.");
        }

        $cidrs = [];

        foreach ($raw as $cidr) {
            if (! is_string($cidr) || ! str_contains($cidr, '/')) {
                throw new InvalidArgumentException("{$label}[{$index}] has an invalid CIDR.");
            }

            [$network, $bits] = explode('/', $cidr, 2);

            if (IpClassifier::normalize($network) === null || ! ctype_digit($bits)) {
                throw new InvalidArgumentException("{$label}[{$index}] has an invalid CIDR: {$cidr}");
            }

            $prefix = (int) $bits;
            $max = str_contains((string) $network, ':') ? 128 : 32;

            if ($prefix < $max - 24) {
                throw new InvalidArgumentException(
                    "{$label}[{$index}] CIDR {$cidr} is too broad; use at most a /".($max - 24).' or narrower.',
                );
            }

            if ($prefix > $max) {
                throw new InvalidArgumentException("{$label}[{$index}] CIDR {$cidr} has an impossible prefix.");
            }

            $cidrs[] = $network.'/'.$prefix;
        }

        return $cidrs;
    }
}
