<?php

declare(strict_types=1);

namespace App\Security\Target;

/**
 * Normalizes the host part of a URL before any policy decision is made.
 *
 * This is where alternate IPv4 notations are defused. `127.0.0.1`,
 * `2130706433`, `0x7f000001`, `0177.0.0.1` and `127.1` are the same address,
 * and a policy that only understands the dotted form can be walked past with
 * the others.
 */
final class HostNormalizer
{
    /**
     * @return string|null the canonical host, or null when it is not a valid
     *                     hostname/IP address (callers must fail closed)
     */
    public static function normalize(string $rawHost): ?string
    {
        $host = strtolower(trim($rawHost));

        // Bracketed IPv6 literal, as it appears in a URL: [::1]
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $host = substr($host, 1, -1);
        }

        // A fully qualified name may carry a trailing root dot.
        $host = rtrim($host, '.');

        if ($host === '') {
            return null;
        }

        // Canonical IP (handles IPv6 forms, including ::ffff: and zone ids).
        $ip = IpClassifier::normalize($host);
        if ($ip !== null) {
            return $ip;
        }

        // Legacy IPv4 notations that inet_pton rejects.
        $legacy = self::parseLegacyIpv4($host);
        if ($legacy !== null) {
            return $legacy;
        }

        // Non-ASCII hostnames must be punycoded by the operator; we do not
        // guess, because a wrong guess is how IDN homograph bypasses happen.
        if (preg_match('/[^\x20-\x7e]/', $host) === 1) {
            return null;
        }

        if (strlen($host) > 253) {
            return null;
        }

        // A hostname: labels of alphanumerics/hyphen, not starting or ending
        // with a hyphen. Underscores are tolerated (common in internal DNS).
        $label = '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?';
        if (preg_match('/^'.$label.'(?:\.'.$label.')*$/', $host) !== 1) {
            return null;
        }

        return $host;
    }

    /**
     * Parse the inet_aton shorthand forms into a dotted-quad.
     *
     * `a`            -> 32 bits
     * `a.b`          -> 8 + 24 bits
     * `a.b.c`        -> 8 + 8 + 16 bits
     * `a.b.c.d`      -> 8 + 8 + 8 + 8 bits
     *
     * Each component may be decimal, octal (leading 0) or hexadecimal (0x).
     */
    public static function parseLegacyIpv4(string $host): ?string
    {
        if (preg_match('/^[0-9a-fx.]+$/i', $host) !== 1) {
            return null;
        }

        $parts = explode('.', $host);
        if (count($parts) > 4) {
            return null;
        }

        $numbers = [];
        foreach ($parts as $part) {
            if ($part === '') {
                return null;
            }

            $value = self::parseComponent($part);
            if ($value === null) {
                return null;
            }

            $numbers[] = $value;
        }

        $last = array_pop($numbers);
        $maxLast = 2 ** (32 - 8 * count($numbers));

        if ($last >= $maxLast) {
            return null;
        }

        foreach ($numbers as $number) {
            if ($number > 255) {
                return null;
            }
        }

        $value = $last;
        foreach ($numbers as $index => $number) {
            $value += $number * 2 ** (32 - 8 * ($index + 1));
        }

        return long2ip((int) $value);
    }

    private static function parseComponent(string $part): ?int
    {
        if (preg_match('/^0x[0-9a-f]+$/i', $part) === 1) {
            return (int) hexdec(substr($part, 2));
        }

        if (preg_match('/^0[0-7]+$/', $part) === 1) {
            return (int) octdec(substr($part, 1));
        }

        if (preg_match('/^[0-9]+$/', $part) === 1) {
            return (int) $part;
        }

        return null;
    }
}
