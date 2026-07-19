<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class WapitiScanner extends BaseDockerScanner
{
    protected string $toolName = 'wapiti';

    protected array $defaultArgs = ['--scope', 'folder', '--skip', 'brute_login,permanent_xss'];

    public function name(): string
    {
        return 'wapiti';
    }

    public function description(): string
    {
        return 'Web application vulnerability scanner for XSS, SQLi, and injections';
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

        $vulnerabilities = $data['vulnerabilities'] ?? $data;

        if (!empty($vulnerabilities)) {
            $vulnCount = 0;
            foreach ($vulnerabilities as $category => $items) {
                if (is_string($category) && is_array($items)) {
                    foreach ($items as $item) {
                        $title = $item['title'] ?? $item['name'] ?? "{$category} finding";
                        $description = $item['description'] ?? $item['info'] ?? '';
                        $endpoint = $item['endpoint'] ?? $item['url'] ?? '';
                        $severity = $item['severity'] ?? 'medium';

                        $results->add($this->createResult(
                            $severity,
                            "Wapiti: {$title}",
                            "{$description} at {$endpoint}",
                            [
                                'category' => $category,
                                'endpoint' => $endpoint,
                                'description' => $description,
                            ]
                        ));
                        $vulnCount++;
                    }
                }
            }

            if ($vulnCount > 0) {
                $results->add($this->createResult(
                    'info',
                    'Wapiti scan complete',
                    sprintf('Wapiti identified %d vulnerability/ies', $vulnCount),
                    ['total_findings' => $vulnCount]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No Wapiti findings',
                'Wapiti did not identify any vulnerabilities'
            ));
        }

        return $results;
    }
}
