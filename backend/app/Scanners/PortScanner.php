<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\DTOs\ScannerOutcome;
use App\Enums\ScannerCategory;
use App\Enums\ScannerIntrusiveness;
use App\Models\Project;

class PortScanner extends BaseScanner
{
    private array $commonPorts = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1433, 1521, 2049, 3306,
        3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443,
        9000, 9090, 27017,
    ];

    public function name(): string
    {
        return 'port_scanner';
    }

    public function description(): string
    {
        return 'Scans for open ports on the target host';
    }

    public function category(): string
    {
        return ScannerCategory::Network->value;
    }

    public function severity(): string
    {
        return 'medium';
    }

    /**
     * Connects to the target host on many ports, so it is an active scanner.
     */
    public function intrusiveness(): ScannerIntrusiveness
    {
        return ScannerIntrusiveness::Active;
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $host = parse_url($project->target_url, PHP_URL_HOST) ?? $project->target_url;
        $openPorts = [];

        // Only probe ports the operator authorized for this target. Scanning
        // ports that are not in the approved scope would be an out-of-scope
        // action, so the list is intersected with the approval instead of
        // being sent wholesale.
        $approved = $this->approvedPorts($context);
        if ($approved === []) {
            return $results->withOutcome(ScannerOutcome::blocked('No ports were approved for this target.'));
        }

        $ports = array_values(array_intersect($this->commonPorts, $approved));
        $perPortTimeout = max(1, $this->timeout / max(1, count($ports)));

        foreach ($ports as $port) {
            try {
                $errno = 0;
                $errstr = '';
                $conn = @fsockopen($host, $port, $errno, $errstr, $perPortTimeout);
                if (is_resource($conn)) {
                    fclose($conn);
                    $openPorts[] = $port;
                }
            } catch (\Throwable) {
                continue;
            }
        }

        if (!empty($openPorts)) {
            $serviceNames = $this->getServiceNames($openPorts);
            $results->add($this->createResult(
                'medium',
                'Open ports detected',
                sprintf('Found %d open port(s) on %s', count($openPorts), $host),
                ['open_ports' => $openPorts, 'services' => $serviceNames]
            ));

            foreach ($openPorts as $port) {
                $service = $serviceNames[$port] ?? 'unknown';
                $severity = $this->getPortSeverity($port);
                $results->add($this->createResult(
                    $severity,
                    "Open port: {$port}/{$service}",
                    "Port {$port} ({$service}) is open on {$host}",
                    ['port' => $port, 'service' => $service]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No common ports open',
                "No common open ports detected on {$host}",
                ['scanned_ports' => $ports]
            ));
        }

        return $results;
    }

    /**
     * @param  array<string, mixed>  $context
     * @return list<int>
     */
    private function approvedPorts(array $context): array
    {
        $decision = $context['scope'] ?? null;
        $ports = $decision?->ports ?? $context['ports'] ?? [];

        return array_values(array_unique(array_map('intval', array_filter((array) $ports, 'is_numeric'))));
    }

    private function getServiceNames(array $ports): array
    {
        $services = [
            21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP',
            53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 135 => 'RPC',
            139 => 'NetBIOS', 143 => 'IMAP', 443 => 'HTTPS', 445 => 'SMB',
            993 => 'IMAPS', 995 => 'POP3S', 1433 => 'MSSQL', 1521 => 'Oracle',
            2049 => 'NFS', 3306 => 'MySQL', 3389 => 'RDP', 5432 => 'PostgreSQL',
            5900 => 'VNC', 5985 => 'WinRM-HTTP', 5986 => 'WinRM-HTTPS',
            6379 => 'Redis', 8080 => 'HTTP-Alt', 8443 => 'HTTPS-Alt',
            9000 => 'PHP-FPM', 9090 => 'WebAdmin', 27017 => 'MongoDB',
        ];
        return array_intersect_key($services, array_flip($ports));
    }

    private function getPortSeverity(int $port): string
    {
        return in_array($port, [21, 23, 135, 139, 445, 3389]) ? 'high' : 'medium';
    }
}
