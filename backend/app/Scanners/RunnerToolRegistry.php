<?php

declare(strict_types=1);

namespace App\Scanners;

use App\Enums\ScannerIntrusiveness;

/**
 * Mirror of the Runner's tool registry (runner/src/tools.mjs).
 *
 * The Runner is authoritative: it re-validates the tool name and builds the
 * argv itself. This mirror exists so the API can classify intrusiveness for
 * approval purposes without executing anything.
 *
 * Unknown tools are classified Active — an unclassified tool must never be
 * treated as safe.
 */
final class RunnerToolRegistry
{
    /** @var array<string, ScannerIntrusiveness> */
    public const TOOLS = [
        'nmap' => ScannerIntrusiveness::Active,
        'httpx' => ScannerIntrusiveness::Passive,
        'whatweb' => ScannerIntrusiveness::Passive,
        'dnsrecon' => ScannerIntrusiveness::Active,
        'subfinder' => ScannerIntrusiveness::Passive,
        'amass' => ScannerIntrusiveness::Active,
        'theharvester' => ScannerIntrusiveness::Passive,
        'dirsearch' => ScannerIntrusiveness::Active,
        'ffuf' => ScannerIntrusiveness::Active,
        'katana' => ScannerIntrusiveness::Active,
        'hakrawler' => ScannerIntrusiveness::Active,
        'gau' => ScannerIntrusiveness::Passive,
        'waybackurls' => ScannerIntrusiveness::Passive,
        'nuclei' => ScannerIntrusiveness::Active,
        'nikto' => ScannerIntrusiveness::Active,
        'wapiti' => ScannerIntrusiveness::Active,
        'sslscan' => ScannerIntrusiveness::Passive,
        'testssl' => ScannerIntrusiveness::Passive,
    ];

    public static function has(string $tool): bool
    {
        return isset(self::TOOLS[$tool]);
    }

    public static function intrusiveness(string $tool): ScannerIntrusiveness
    {
        return self::TOOLS[$tool] ?? ScannerIntrusiveness::Active;
    }

    /** @return list<string> */
    public static function names(): array
    {
        return array_keys(self::TOOLS);
    }

    /**
     * Does this registry version match what the Runner reports?
     *
     * @param  list<string>  $runnerTools
     * @return list<string>  tools that disagree
     */
    public static function drift(array $runnerTools): array
    {
        return array_values(array_diff(self::names(), $runnerTools));
    }
}
