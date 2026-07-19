<?php

namespace App\DTOs;

use App\Models\Project;
use App\Models\Scan;

class ScanContext
{
    public function __construct(
        public readonly Project $project,
        public readonly Scan $scan,
        public readonly array $completedScanners = [],
        public readonly array $results = [],
        public readonly array $reasoningChain = [],
        public readonly array $availableScanners = [],
        public readonly array $detectedTechnologies = [],
        public readonly array $openPorts = [],
        public readonly bool $hasHttpService = false,
        public readonly bool $hasHttpsService = false,
        public readonly bool $hasApiEndpoints = false,
        public readonly ?int $httpStatusCode = null,
    ) {}

    public function addResult(string $scannerName, array $results): self
    {
        $newResults = $this->results;
        $newResults[$scannerName] = $results;

        $newTechnologies = $this->detectedTechnologies;
        $newPorts = $this->openPorts;
        $hasHttp = $this->hasHttpService;
        $hasHttps = $this->hasHttpsService;
        $hasApi = $this->hasApiEndpoints;
        $httpStatus = $this->httpStatusCode;

        foreach ($results as $result) {
            $details = $result['details'] ?? [];
            $title = $result['title'] ?? '';

            if ($scannerName === 'technology_detector' && isset($details['technologies'])) {
                $newTechnologies = array_merge($newTechnologies, $details['technologies']);
            }
            if ($scannerName === 'whatweb' && isset($details['technologies'])) {
                $newTechnologies = array_merge($newTechnologies, array_keys($details['technologies']));
            }
            if ($scannerName === 'httpx' && isset($details['technologies'])) {
                $newTechnologies = array_merge($newTechnologies, $details['technologies']);
            }

            if (in_array($scannerName, ['port_scanner', 'nmap'])) {
                if (isset($details['open_ports'])) {
                    foreach ($details['open_ports'] as $port) {
                        $portNum = is_array($port) ? ($port['port'] ?? 0) : $port;
                        $newPorts[] = $portNum;
                        if ($portNum === 80 || $portNum === 8080) $hasHttp = true;
                        if ($portNum === 443 || $portNum === 8443) $hasHttps = true;
                    }
                }
                if (isset($details['port'])) {
                    $portNum = $details['port'];
                    $newPorts[] = $portNum;
                    if ($portNum === 80 || $portNum === 8080) $hasHttp = true;
                    if ($portNum === 443 || $portNum === 8443) $hasHttps = true;
                }
            }

            if ($scannerName === 'api_assessment') {
                if (!empty($details['api_endpoints'])) $hasApi = true;
            }

            if ($scannerName === 'http_analyzer' && isset($details['status_code'])) {
                $httpStatus = (int) $details['status_code'];
            }
        }

        return new self(
            project: $this->project,
            scan: $this->scan,
            completedScanners: [...$this->completedScanners, $scannerName],
            results: $newResults,
            reasoningChain: $this->reasoningChain,
            availableScanners: $this->availableScanners,
            detectedTechnologies: array_unique($newTechnologies),
            openPorts: array_unique($newPorts),
            hasHttpService: $hasHttp,
            hasHttpsService: $hasHttps,
            hasApiEndpoints: $hasApi,
            httpStatusCode: $httpStatus,
        );
    }

    public function addReasoning(string $reasoning): self
    {
        return new self(
            project: $this->project,
            scan: $this->scan,
            completedScanners: $this->completedScanners,
            results: $this->results,
            reasoningChain: [...$this->reasoningChain, $reasoning],
            availableScanners: $this->availableScanners,
            detectedTechnologies: $this->detectedTechnologies,
            openPorts: $this->openPorts,
            hasHttpService: $this->hasHttpService,
            hasHttpsService: $this->hasHttpsService,
            hasApiEndpoints: $this->hasApiEndpoints,
            httpStatusCode: $this->httpStatusCode,
        );
    }

    public function toArray(): array
    {
        return [
            'target' => $this->project->target_url,
            'project_name' => $this->project->name,
            'completed_scanners' => $this->completedScanners,
            'results_summary' => $this->summarizeResults(),
            'reasoning_history' => $this->reasoningChain,
            'detected_technologies' => $this->detectedTechnologies,
            'open_ports' => $this->openPorts,
            'has_http' => $this->hasHttpService,
            'has_https' => $this->hasHttpsService,
            'has_api' => $this->hasApiEndpoints,
            'http_status' => $this->httpStatusCode,
        ];
    }

    private function summarizeResults(): array
    {
        $summary = [];
        foreach ($this->results as $scanner => $results) {
            $summary[$scanner] = [
                'finding_count' => count($results),
                'severity_breakdown' => array_count_values(
                    array_map(fn($r) => $r['severity'] ?? 'info', $results)
                ),
            ];
        }
        return $summary;
    }

    public function getTechnologiesSummary(): string
    {
        if (empty($this->detectedTechnologies)) {
            return 'No technologies detected';
        }
        return implode(', ', $this->detectedTechnologies);
    }

    public function getPortsSummary(): string
    {
        if (empty($this->openPorts)) {
            return 'No open ports detected';
        }
        return implode(', ', array_map(fn($p) => "Port {$p}", $this->openPorts));
    }
}
