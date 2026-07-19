<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class AmassScanner extends BaseDockerScanner
{
    protected string $toolName = 'amass';

    protected array $defaultArgs = ['-silent', '-timeout', '5'];

    public function name(): string
    {
        return 'amass';
    }

    public function description(): string
    {
        return 'In-depth subdomain enumeration and network mapping';
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
            if (isset($entry['name'])) {
                $subdomains[] = $entry['name'];
            }
        }

        $subdomains = array_unique($subdomains);

        if (!empty($subdomains)) {
            $results->add($this->createResult(
                'medium',
                'Subdomains discovered via Amass',
                sprintf('Found %d subdomain(s) via Amass enumeration', count($subdomains)),
                ['subdomains' => $subdomains]
            ));

            foreach (array_slice($subdomains, 0, 10) as $sub) {
                $results->add($this->createResult(
                    'low',
                    "Subdomain: {$sub}",
                    "Discovered subdomain via Amass: {$sub}",
                    ['subdomain' => $sub]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No subdomains via Amass',
                'Amass did not discover additional subdomains'
            ));
        }

        return $results;
    }
}
