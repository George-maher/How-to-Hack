<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class NiktoScanner extends BaseDockerScanner
{
    protected string $toolName = 'nikto';

    public function name(): string
    {
        return 'nikto';
    }

    public function description(): string
    {
        return 'Web server scanner for known vulnerabilities and misconfigurations';
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
        $data = $this->safeJsonDecode($rawOutput);

        $vulns = $data['vulnerabilities'] ?? (isset($data[0]) ? $data : []);

        if (!empty($vulns)) {
            foreach ($vulns as $vuln) {
                $description = $vuln['description'] ?? $vuln['msg'] ?? 'Unknown finding';
                $uri = $vuln['uri'] ?? $vuln['path'] ?? '/';
                $method = $vuln['method'] ?? 'GET';
                $reference = $vuln['reference'] ?? $vuln['ref'] ?? '';

                $severity = 'medium';
                if (stripos($description, 'critical') !== false || stripos($description, 'remote') !== false) {
                    $severity = 'high';
                }
                if (stripos($description, 'xss') !== false || stripos($description, 'sql') !== false) {
                    $severity = 'high';
                }

                $results->add($this->createResult(
                    $severity,
                    "Nikto: {$description}",
                    "{$method} {$uri} - {$description}" . ($reference ? " [Ref: {$reference}]" : ''),
                    [
                        'uri' => $uri,
                        'method' => $method,
                        'description' => $description,
                        'reference' => $reference,
                    ]
                ));
            }

            $results->add($this->createResult(
                'info',
                'Nikto scan complete',
                sprintf('Nikto identified %d finding(s)', count($vulns)),
                ['total_findings' => count($vulns)]
            ));
        } else {
            $results->add($this->createResult(
                'info',
                'No Nikto findings',
                'Nikto did not identify any vulnerabilities'
            ));
        }

        return $results;
    }
}
