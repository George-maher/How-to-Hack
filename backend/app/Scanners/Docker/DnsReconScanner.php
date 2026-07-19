<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class DnsReconScanner extends BaseDockerScanner
{
    protected string $toolName = 'dnsrecon';

    public function name(): string
    {
        return 'dnsrecon';
    }

    public function description(): string
    {
        return 'DNS record enumeration and zone transfer detection';
    }

    public function category(): string
    {
        return ScannerCategory::Reconnaissance->value;
    }

    public function severity(): string
    {
        return 'info';
    }

    protected function parseResults(string $rawOutput, Project $project): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $data = $this->safeJsonDecode($rawOutput);

        if (!empty($data['records'])) {
            $recordCount = 0;
            foreach ($data['records'] as $type => $records) {
                $recordCount += count($records);
            }

            $results->add($this->createResult(
                'info',
                'DNS records enumerated',
                sprintf('Found %d DNS record(s) across %d type(s) for %s',
                    $recordCount,
                    count($data['records']),
                    $data['target'] ?? 'target'
                ),
                $data['records']
            ));

            if (!empty($data['records']['TXT'])) {
                foreach ($data['records']['TXT'] as $txt) {
                    if (preg_match('/(key=|secret=|password=|token=)/i', $txt)) {
                        $results->add($this->createResult(
                            'medium',
                            'Sensitive data in DNS TXT record',
                            "TXT record contains potential secrets: " . substr($txt, 0, 100),
                            ['txt_record' => $txt]
                        ));
                    }
                }
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No DNS records found',
                'DNS enumeration did not return any records'
            ));
        }

        return $results;
    }
}
