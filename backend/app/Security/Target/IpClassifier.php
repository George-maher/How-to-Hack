<?php

declare(strict_types=1);

namespace App\Security\Target;

/**
 * Classifies IP literals (v4 and v6) into the classes the policy cares about.
 *
 * The same set of rules runs in the Runner (see runner/lib/policy.mjs), so a
 * target cannot pass one boundary and fail the other.
 *
 * IPv6 handling is deliberately thorough: IPv4-mapped (`::ffff:127.0.0.1`),
 * NAT64 (`64:ff9b::7f00:1`), 6to4 and ULA addresses all reach an IPv4 or a
 * special-purpose range eventually, and each of those would otherwise be a way
 * to smuggle a loopback or metadata address past a naive `filter_var` check.
 */
final class IpClassifier
{
    /** @var array<string, IpClass> */
    private const IPV4_BLOCKS = [
        '0.0.0.0/8' => IpClass::Unspecified,
        '10.0.0.0/8' => IpClass::Private,
        '100.64.0.0/10' => IpClass::CarrierGradeNat,
        '127.0.0.0/8' => IpClass::Loopback,
        '169.254.0.0/16' => IpClass::LinkLocal,
        '172.16.0.0/12' => IpClass::Private,
        '192.0.0.0/24' => IpClass::Reserved,
        '192.0.2.0/24' => IpClass::Reserved,
        '192.168.0.0/16' => IpClass::Private,
        '198.18.0.0/15' => IpClass::Reserved,
        '198.51.100.0/24' => IpClass::Reserved,
        '203.0.113.0/24' => IpClass::Reserved,
        '224.0.0.0/4' => IpClass::Multicast,
        '240.0.0.0/4' => IpClass::Reserved,
    ];

    /**
     * Endpoints that answer with cloud credentials. Checked before every other
     * rule and never permittable.
     *
     * @var list<string>
     */
    private const METADATA_ADDRESSES = [
        '169.254.169.254',  // AWS / GCP / Azure / OpenStack IMDS
        '169.254.170.2',    // AWS ECS task metadata
        '169.254.169.253',  // AWS DNS
        'fd00:ec2::254',    // AWS IPv6 IMDS
        'fe80::a9fe:a9fe',  // Azure wire-server (link-local form)
    ];

    /**
     * @var array<string, IpClass>
     */
    private const IPV6_BLOCKS = [
        '::/128' => IpClass::Unspecified,
        '::1/128' => IpClass::Loopback,
        '100::/64' => IpClass::Reserved,
        '2001::/32' => IpClass::Reserved,
        '2001:db8::/32' => IpClass::Reserved,
        '2002::/16' => IpClass::Reserved,
        'fc00::/7' => IpClass::Private,
        'fe80::/10' => IpClass::LinkLocal,
        'ff00::/8' => IpClass::Multicast,
        '64:ff9b:1::/48' => IpClass::Reserved,
    ];

    public function classify(string $ip): IpClass
    {
        $normalized = self::normalize($ip);

        if ($normalized === null) {
            return IpClass::Reserved;
        }

        if (in_array($normalized, self::METADATA_ADDRESSES, true)) {
            return IpClass::CloudMetadata;
        }

        $packed = @inet_pton($normalized);
        if ($packed === false) {
            return IpClass::Reserved;
        }

        if (strlen($packed) === 4) {
            return $this->classifyIpv4($packed);
        }

        return $this->classifyIpv6($packed, $normalized);
    }

    /**
     * Canonical textual form (what we store and compare), or null when the input
     * is not an IP address at all.
     */
    public static function normalize(string $ip): ?string
    {
        $candidate = trim($ip);

        // Strip an IPv6 zone identifier: fe80::1%eth0 is the same address.
        if (str_contains($candidate, '%')) {
            [$candidate] = explode('%', $candidate, 2);
        }

        if ($candidate === '') {
            return null;
        }

        $packed = @inet_pton($candidate);
        if ($packed === false) {
            return null;
        }

        return inet_ntop($packed) ?: null;
    }

    public static function isIpLiteral(string $host): bool
    {
        return self::normalize($host) !== null;
    }

    private function classifyIpv4(string $packed): IpClass
    {
        foreach (self::IPV4_BLOCKS as $cidr => $class) {
            if (self::inCidr($packed, $cidr)) {
                return $class;
            }
        }

        return IpClass::Public;
    }

    private function classifyIpv6(string $packed, string $text): IpClass
    {
        // IPv4-mapped (::ffff:a.b.c.d): classify the embedded IPv4 address.
        if (str_starts_with($text, '::ffff:') || str_starts_with($text, '::ffff:0:')) {
            $embedded = substr($packed, 12, 4);

            return $this->classifyIpv4($embedded);
        }

        // NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 address.
        if (self::inCidr($packed, '64:ff9b::/96')) {
            return $this->classifyIpv4(substr($packed, 12, 4));
        }

        foreach (self::IPV6_BLOCKS as $cidr => $class) {
            if (self::inCidr($packed, $cidr)) {
                return $class;
            }
        }

        return IpClass::Public;
    }

    /**
     * True when the packed address falls inside the given CIDR.
     */
    public static function inCidr(string $packedIp, string $cidr): bool
    {
        [$network, $bits] = array_pad(explode('/', $cidr, 2), 2, null);

        $packedNetwork = @inet_pton((string) $network);
        if ($packedNetwork === false || strlen($packedNetwork) !== strlen($packedIp)) {
            return false;
        }

        $prefix = $bits === null ? strlen($packedIp) * 8 : (int) $bits;
        if ($prefix < 0 || $prefix > strlen($packedIp) * 8) {
            return false;
        }

        $wholeBytes = intdiv($prefix, 8);
        $remainderBits = $prefix % 8;

        if ($wholeBytes > 0 && substr($packedIp, 0, $wholeBytes) !== substr($packedNetwork, 0, $wholeBytes)) {
            return false;
        }

        if ($remainderBits === 0) {
            return true;
        }

        $mask = 0xFF << (8 - $remainderBits) & 0xFF;

        return (ord($packedIp[$wholeBytes]) & $mask) === (ord($packedNetwork[$wholeBytes]) & $mask);
    }
}
