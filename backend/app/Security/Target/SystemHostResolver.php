<?php

declare(strict_types=1);

namespace App\Security\Target;

/**
 * Resolves hostnames through the system resolver.
 *
 * Both address families are requested. A failure to resolve is not an error
 * here — the policy turns an empty answer into `unresolved`, which is a denial.
 */
final class SystemHostResolver implements HostResolver
{
    public function __construct(private readonly int $timeoutSeconds = 3)
    {
    }

    public function resolve(string $host): array
    {
        $addresses = [];

        // Prefer dns_get_record: it can return A and AAAA together.
        if (function_exists('dns_get_record')) {
            foreach (['A' => DNS_A, 'AAAA' => DNS_AAAA] as $type => $flag) {
                $records = @dns_get_record($host, $flag);

                if (! is_array($records)) {
                    continue;
                }

                foreach ($records as $record) {
                    $value = $record['ip'] ?? $record['ipv6'] ?? null;
                    if (is_string($value)) {
                        $addresses[] = $value;
                    }
                }
            }
        }

        // Fallback for hosts files / single-stack environments.
        if ($addresses === []) {
            $resolved = @gethostbynamel($host);
            if (is_array($resolved)) {
                $addresses = $resolved;
            }
        }

        $canonical = [];
        foreach ($addresses as $address) {
            $normalized = IpClassifier::normalize((string) $address);
            if ($normalized !== null) {
                $canonical[$normalized] = true;
            }
        }

        return array_keys($canonical);
    }
}
