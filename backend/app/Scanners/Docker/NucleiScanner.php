<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class NucleiScanner extends BaseDockerScanner
{
    protected string $toolName = 'nuclei';

    protected array $defaultArgs = ['-severity', 'low,medium,high,critical'];

    public function name(): string
    {
        return 'nuclei';
    }

    public function description(): string
    {
        return 'Fast vulnerability scanner based on YAML templates';
    }

    public function category(): string
    {
        return ScannerCategory::WebApplication->value;
    }

    public function severity(): string
    {
        return 'high';
    }

    protected function parseResults(string $rawOutput, Project $project): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $lines = array_filter(explode("\n", trim($rawOutput)));

        $vulnerabilities = [];
        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (!empty($entry)) {
                $vulnerabilities[] = $entry;
            }
        }

        if (!empty($vulnerabilities)) {
            $matchedVulns = [];
            foreach ($vulnerabilities as $vuln) {
                $name = $vuln['info']['name'] ?? $vuln['template-id'] ?? 'Unknown';
                $severity = $vuln['info']['severity'] ?? $vuln['severity'] ?? 'medium';
                $matched = $vuln['matched-at'] ?? $vuln['host'] ?? '';
                $extracted = $vuln['extracted-results'] ?? [];
                $type = $vuln['type'] ?? 'template';

                $sev = match ($severity) {
                    'critical' => 'critical',
                    'high' => 'high',
                    'medium' => 'medium',
                    'low' => 'low',
                    default => 'info',
                };

                $results->add($this->createResult(
                    $sev,
                    "Nuclei: {$name}",
                    "Template '{$name}' matched at {$matched}" . (!empty($extracted) ? ' - ' . json_encode($extracted) : ''),
                    [
                        'template' => $name,
                        'matched_at' => $matched,
                        'severity' => $severity,
                        'type' => $type,
                        'extracted' => $extracted,
                        'raw' => $vuln,
                    ]
                ));

                $matchedVulns[] = $name;
            }

            $results->add($this->createResult(
                'info',
                'Nuclei scan complete',
                sprintf('Nuclei identified %d potential vulnerability/ies', count($vulnerabilities)),
                ['vulnerabilities_found' => $matchedVulns]
            ));
        } else {
            $results->add($this->createResult(
                'info',
                'No vulnerabilities detected',
                'Nuclei did not identify any vulnerabilities'
            ));
        }

        return $results;
    }
}
