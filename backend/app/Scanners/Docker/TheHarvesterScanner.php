<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class TheHarvesterScanner extends BaseDockerScanner
{
    protected string $toolName = 'theharvester';

    public function name(): string
    {
        return 'theharvester';
    }

    public function description(): string
    {
        return 'Email, subdomain and host enumeration from public sources';
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

        $hosts = $data['hosts'] ?? [];
        $emails = $data['emails'] ?? [];

        $summary = [];
        if (!empty($hosts)) {
            $summary['hosts'] = $hosts;
            $results->add($this->createResult(
                'info',
                'Hosts discovered via theHarvester',
                sprintf('Found %d host(s) from public sources', count($hosts)),
                ['hosts' => $hosts]
            ));
        }

        if (!empty($emails)) {
            $summary['emails'] = $emails;
            $results->add($this->createResult(
                'low',
                'Email addresses discovered',
                sprintf('Found %d email address(es) from public sources', count($emails)),
                ['emails' => $emails]
            ));
        }

        if (empty($hosts) && empty($emails)) {
            $results->add($this->createResult(
                'info',
                'No public information discovered',
                'theHarvester did not find hosts or emails from public sources'
            ));
        }

        return $results;
    }
}
