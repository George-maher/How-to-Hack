<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class WhoisLookup extends BaseScanner
{
    public function name(): string
    {
        return 'whois_lookup';
    }

    public function description(): string
    {
        return 'Performs WHOIS lookup for domain registration information';
    }

    public function category(): string
    {
        return ScannerCategory::InformationDisclosure->value;
    }

    public function severity(): string
    {
        return 'info';
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $host = parse_url($project->target_url, PHP_URL_HOST) ?? $project->target_url;
        $host = preg_replace('/^www\./', '', $host);

        $whoisServers = [
            'com' => 'whois.verisign-grs.com',
            'net' => 'whois.verisign-grs.com',
            'org' => 'whois.pir.org',
            'io' => 'whois.nic.io',
            'dev' => 'whois.nic.google',
            'co.uk' => 'whois.nic.uk',
            'gov' => 'whois.dotgov.gov',
            'edu' => 'whois.educause.edu',
        ];

        $parts = explode('.', $host);
        $extension = count($parts) >= 2 ? implode('.', array_slice($parts, -2)) : 'com';
        if (!isset($whoisServers[$extension])) {
            $extension = count($parts) >= 1 ? end($parts) : 'com';
        }
        $server = $whoisServers[$extension] ?? 'whois.verisign-grs.com';

        try {
            $socket = @fsockopen($server, 43, $errno, $errstr, $this->timeout);
            if (is_resource($socket)) {
                fwrite($socket, $host . "\r\n");
                $response = '';
                while (!feof($socket)) {
                    $response .= fread($socket, 4096);
                }
                fclose($socket);

                if (!empty($response)) {
                    $info = $this->parseWhoisResponse($response);
                    $results->add($this->createResult(
                        'info',
                        'WHOIS information retrieved',
                        "Successfully retrieved WHOIS data for {$host}",
                        ['whois_info' => $info, 'raw_response' => substr($response, 0, 2000)]
                    ));
                }
            } else {
                $results->add($this->createResult(
                    'info',
                    'WHOIS lookup unavailable',
                    "Could not connect to WHOIS server: {$errstr}"
                ));
            }
        } catch (\Throwable $e) {
            $results->add($this->createResult(
                'info',
                'WHOIS lookup failed',
                "WHOIS lookup failed: {$e->getMessage()}"
            ));
        }

        return $results;
    }

    private function parseWhoisResponse(string $response): array
    {
        $info = [];
        $lines = explode("\n", $response);
        $relevantFields = [
            'Domain Name', 'Registry Domain ID', 'Registrar',
            'Creation Date', 'Registry Expiry Date', 'Updated Date',
            'Name Server', 'Registrant', 'Admin', 'Tech',
            'Status', 'DNSSEC',
        ];

        foreach ($lines as $line) {
            foreach ($relevantFields as $field) {
                if (stripos($line, $field) === 0) {
                    $parts = explode(':', $line, 2);
                    if (count($parts) === 2) {
                        $key = trim($parts[0]);
                        $value = trim($parts[1]);
                        if (!isset($info[$key])) {
                            $info[$key] = $value;
                        } elseif (is_array($info[$key])) {
                            $info[$key][] = $value;
                        } else {
                            $info[$key] = [$info[$key], $value];
                        }
                    }
                }
            }
        }

        return $info;
    }
}
