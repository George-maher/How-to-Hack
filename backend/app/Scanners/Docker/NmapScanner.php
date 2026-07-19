<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class NmapScanner extends BaseDockerScanner
{
    protected string $toolName = 'nmap';

    protected array $defaultArgs = ['-sV', '--top-ports', '1000'];

    public function name(): string
    {
        return 'nmap';
    }

    public function description(): string
    {
        return 'Advanced port scanner with service and OS detection via Nmap';
    }

    public function category(): string
    {
        return ScannerCategory::Network->value;
    }

    public function severity(): string
    {
        return 'medium';
    }

    protected function parseResults(string $rawOutput, Project $project): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $data = $this->safeJsonDecode($rawOutput);

        $openPorts = [];
        foreach ($data as $entry) {
            if (isset($entry['port'])) {
                $openPorts[] = $entry;
            }
        }

        if (!empty($openPorts)) {
            $results->add($this->createResult(
                'medium',
                'Open ports detected via Nmap',
                sprintf('Found %d open port(s) via Nmap scan', count($openPorts)),
                ['open_ports' => $openPorts]
            ));

            foreach ($openPorts as $port) {
                $severity = in_array($port['port'], [21, 23, 135, 139, 445, 3389]) ? 'high' : 'medium';
                $results->add($this->createResult(
                    $severity,
                    "Open port: {$port['port']}/{$port['service']}",
                    "Port {$port['port']} ({$port['service']}) is open",
                    $port
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No open ports detected via Nmap',
                'Nmap scan did not detect any open ports among the top 1000'
            ));
        }

        return $results;
    }

    public function dependencies(): array
    {
        return [];
    }
}
