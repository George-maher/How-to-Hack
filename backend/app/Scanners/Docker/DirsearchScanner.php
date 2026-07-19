<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class DirsearchScanner extends BaseDockerScanner
{
    protected string $toolName = 'dirsearch';

    public function name(): string
    {
        return 'dirsearch';
    }

    public function description(): string
    {
        return 'Web path discovery and directory brute-forcing';
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

        $paths = $data['results'] ?? $data;

        if (!empty($paths)) {
            foreach ($paths as $path) {
                $url = $path['url'] ?? $path['path'] ?? '';
                $status = $path['status'] ?? 0;
                $severity = $this->getPathSeverity($url, $status);

                $results->add($this->createResult(
                    $severity,
                    "Discovered path: {$url}",
                    "Found accessible path (HTTP {$status}): {$url}",
                    ['url' => $url, 'status' => $status]
                ));
            }

            if ($results->count() > 0) {
                $results->add($this->createResult(
                    'info',
                    'Directory enumeration complete',
                    sprintf('Dirsearch discovered %d accessible path(s)', $results->count()),
                    ['total_found' => $results->count()]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No paths discovered',
                'Dirsearch did not discover any accessible paths'
            ));
        }

        return $results;
    }

    private function getPathSeverity(string $url, int $status): string
    {
        $sensitive = ['/.git', '/.env', '/backup', '/database', '/sql', '/dump', '/.htaccess', '/.htpasswd'];
        $admin = ['/admin', '/login', '/wp-admin', '/administrator', '/panel', '/console'];

        foreach ($sensitive as $pattern) {
            if (stripos($url, $pattern) !== false) {
                return 'critical';
            }
        }
        foreach ($admin as $pattern) {
            if (stripos($url, $pattern) !== false) {
                return 'high';
            }
        }
        if ($status === 200) {
            return 'medium';
        }
        if (in_array($status, [401, 403])) {
            return 'medium';
        }
        return 'low';
    }
}
