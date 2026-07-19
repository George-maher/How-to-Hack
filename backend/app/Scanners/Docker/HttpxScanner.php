<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class HttpxScanner extends BaseDockerScanner
{
    protected string $toolName = 'httpx';

    protected array $defaultArgs = ['-silent', '-title', '-tech-detect', '-status-code', '-content-length'];

    public function name(): string
    {
        return 'httpx';
    }

    public function description(): string
    {
        return 'HTTP probing and technology detection tool';
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
        $lines = array_filter(explode("\n", trim($rawOutput)));

        $detected = [];
        foreach ($lines as $line) {
            $entry = $this->safeJsonDecode($line);
            if (!empty($entry)) {
                $detected[] = $entry;
            }
        }

        if (!empty($detected)) {
            $technologies = [];
            foreach ($detected as $entry) {
                if (isset($entry['tech'])) {
                    $technologies = array_merge($technologies, (array) $entry['tech']);
                }
            }
            $technologies = array_unique($technologies);

            $results->add($this->createResult(
                'info',
                'HTTP endpoints discovered',
                sprintf('Discovered %d HTTP endpoint(s)', count($detected)),
                ['endpoints' => $detected]
            ));

            if (!empty($technologies)) {
                $results->add($this->createResult(
                    'info',
                    'Technologies detected via HTTPX',
                    'Detected technologies: ' . implode(', ', $technologies),
                    ['technologies' => $technologies]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No HTTP endpoints detected',
                'HTTPX did not detect any active HTTP endpoints'
            ));
        }

        return $results;
    }
}
