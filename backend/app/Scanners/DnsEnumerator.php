<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class DnsEnumerator extends BaseScanner
{
    public function name(): string
    {
        return 'dns_enumerator';
    }

    public function description(): string
    {
        return 'Enumerates DNS records for the target domain';
    }

    public function category(): string
    {
        return ScannerCategory::Reconnaissance->value;
    }

    public function severity(): string
    {
        return 'info';
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $host = parse_url($project->target_url, PHP_URL_HOST) ?? $project->target_url;

        $host = preg_replace('/^www\./', '', $host);

        $recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME'];
        $found = [];

        foreach ($recordTypes as $type) {
            try {
                $records = dns_get_record($host, constant("DNS_{$type}"));
                if (!empty($records)) {
                    $found[$type] = $records;
                }
            } catch (\Throwable) {
                continue;
            }
        }

        if (!empty($found)) {
            $results->add($this->createResult(
                'info',
                'DNS records found',
                sprintf('Found %d DNS record type(s) for %s', count($found), $host),
                ['dns_records' => $found]
            ));

            if (isset($found['TXT'])) {
                foreach ($found['TXT'] as $txt) {
                    $txtContent = $txt['txt'] ?? '';
                    if ($this->containsSensitiveDnsInfo($txtContent)) {
                        $results->add($this->createResult(
                            'medium',
                            'Sensitive information in TXT record',
                            "TXT record contains potentially sensitive data",
                            ['record' => $txtContent]
                        ));
                    }
                }
            }

            if (isset($found['MX'])) {
                $results->add($this->createResult(
                    'low',
                    'Mail servers exposed',
                    sprintf('Found %d MX record(s)', count($found['MX'])),
                    ['mx_records' => $found['MX']]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No DNS records found',
                "No DNS records could be enumerated for {$host}"
            ));
        }

        return $results;
    }

    public function dependencies(): array
    {
        return [];
    }

    private function containsSensitiveDnsInfo(string $content): bool
    {
        $patterns = [
            '/key=/i', '/secret=/i', '/password=/i', '/token=/i',
            '/spf/i', '/dkim/i', '/dmarc/i',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }
        return false;
    }
}
