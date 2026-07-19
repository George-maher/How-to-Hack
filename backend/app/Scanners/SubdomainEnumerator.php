<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;
use Illuminate\Support\Facades\Http;

class SubdomainEnumerator extends BaseScanner
{
    private array $commonSubdomains = [
        'www', 'mail', 'admin', 'api', 'dev', 'staging',
        'test', 'blog', 'shop', 'app', 'cdn', 'static',
        'media', 'assets', 'images', 'docs', 'support',
        'help', 'status', 'portal', 'beta', 'demo',
        'stage', 'prod', 'dashboard', 'cms', 'adminer',
        'phpmyadmin', 'webmail', 'owa', 'remote',
        'gitlab', 'jenkins', 'jira', 'confluence',
        'wiki', 'forum', 'community', 'm', 'mobile',
        'secure', 'login', 'register', 'auth',
        'analytics', 'tracking', 'monitor', 'logs',
    ];

    public function name(): string
    {
        return 'subdomain_enumerator';
    }

    public function description(): string
    {
        return 'Enumerates common subdomains of the target domain';
    }

    public function category(): string
    {
        return ScannerCategory::Reconnaissance->value;
    }

    public function severity(): string
    {
        return 'medium';
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $host = parse_url($project->target_url, PHP_URL_HOST) ?? $project->target_url;
        $host = preg_replace('/^www\./', '', $host);
        $found = [];

        foreach ($this->commonSubdomains as $subdomain) {
            $fqdn = "{$subdomain}.{$host}";
            try {
                $ip = gethostbyname($fqdn);
                if ($ip !== $fqdn) {
                    $found[] = ['subdomain' => $fqdn, 'ip' => $ip];
                }
            } catch (\Throwable) {
                continue;
            }
        }

        if (!empty($found)) {
            $results->add($this->createResult(
                'medium',
                "Subdomains discovered for {$host}",
                sprintf('Found %d subdomain(s)', count($found)),
                ['subdomains' => $found]
            ));

            foreach ($found as $entry) {
                $results->add($this->createResult(
                    'low',
                    "Subdomain: {$entry['subdomain']}",
                    "Discovered subdomain {$entry['subdomain']} resolves to {$entry['ip']}",
                    $entry
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No subdomains discovered',
                "No common subdomains were found for {$host}"
            ));
        }

        return $results;
    }
}
