<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class SslScanScanner extends BaseDockerScanner
{
    protected string $toolName = 'sslscan';

    public function name(): string
    {
        return 'sslscan';
    }

    public function description(): string
    {
        return 'SSL/TLS configuration and cipher strength scanner';
    }

    public function category(): string
    {
        return ScannerCategory::Infrastructure->value;
    }

    public function severity(): string
    {
        return 'high';
    }

    protected function parseResults(string $rawOutput, Project $project): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $data = $this->safeJsonDecode($rawOutput);

        if (!empty($data)) {
            $weakCiphers = [];
            $protocols = [];

            if (isset($data['certificate'])) {
                $cert = $data['certificate'];
                $results->add($this->createResult(
                    'info',
                    'SSL certificate details',
                    'Subject: ' . ($cert['subject'] ?? 'N/A') . ', Issuer: ' . ($cert['issuer'] ?? 'N/A'),
                    ['certificate' => $cert]
                ));
            }

            $cipherSuites = $data['cipherSuites'] ?? $data['ciphers'] ?? [];
            foreach ($cipherSuites as $cipher) {
                $name = $cipher['name'] ?? $cipher['cipher'] ?? '';
                $strength = $cipher['strength'] ?? $cipher['encryption'] ?? '';
                $status = $cipher['status'] ?? '';

                if (in_array($status, ['weak', 'insecure']) || stripos($strength, 'weak') !== false) {
                    $weakCiphers[] = $name;
                }
            }

            if (!empty($weakCiphers)) {
                $results->add($this->createResult(
                    'high',
                    'Weak SSL/TLS ciphers detected',
                    sprintf('Found %d weak cipher(s): %s', count($weakCiphers), implode(', ', $weakCiphers)),
                    ['weak_ciphers' => $weakCiphers]
                ));
            }

            $protocolsData = $data['protocols'] ?? [];
            if (!empty($protocolsData)) {
                $deprecated = [];
                foreach ($protocolsData as $proto => $enabled) {
                    if ($enabled && in_array(strtolower($proto), ['ssl2', 'ssl3', 'tls1', 'tls1_0'])) {
                        $deprecated[] = $proto;
                    }
                }
                if (!empty($deprecated)) {
                    $results->add($this->createResult(
                        'high',
                        'Deprecated SSL/TLS protocols enabled',
                        'Deprecated protocols enabled: ' . implode(', ', $deprecated),
                        ['deprecated_protocols' => $deprecated]
                    ));
                }
            }

            if (empty($weakCiphers) && empty($deprecated)) {
                $results->add($this->createResult(
                    'info',
                    'SSL/TLS configuration OK',
                    'No weak ciphers or deprecated protocols detected'
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'SSL scan completed',
                'SSL scan completed with no findings'
            ));
        }

        return $results;
    }
}
