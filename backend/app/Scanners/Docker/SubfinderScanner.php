<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class SubfinderScanner extends BaseDockerScanner
{
    protected string $toolName = 'subfinder';

    public function name(): string
    {
        return 'subfinder';
    }

    public function description(): string
    {
        return 'Passive subdomain enumeration using multiple sources';
    }

    public function category(): string
    {
        return ScannerCategory::Reconnaissance->value;
    }

    public function severity(): string
    {
        return 'medium';
    }

    protected function parseResults(string $rawOutput, Project $project): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $lines = array_filter(explode("\n", trim($rawOutput)));

        $subdomains = [];
        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (isset($entry['host'])) {
                $subdomains[] = $entry['host'];
            } elseif (trim($line)) {
                $subdomains[] = trim($line);
            }
        }

        $subdomains = array_unique($subdomains);

        if (!empty($subdomains)) {
            $results->add($this->createResult(
                'medium',
                'Subdomains discovered via Subfinder',
                sprintf('Found %d subdomain(s) via passive enumeration', count($subdomains)),
                ['subdomains' => $subdomains]
            ));

            foreach (array_slice($subdomains, 0, 15) as $sub) {
                $results->add($this->createResult(
                    'low',
                    "Subdomain: {$sub}",
                    "Discovered subdomain: {$sub}",
                    ['subdomain' => $sub]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No subdomains discovered',
                'Subfinder did not discover any subdomains'
            ));
        }

        return $results;
    }
}
