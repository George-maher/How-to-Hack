<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class SslScanner extends BaseScanner
{
    public function name(): string
    {
        return 'ssl_scanner';
    }

    public function description(): string
    {
        return 'Analyzes SSL/TLS certificate configuration';
    }

    public function category(): string
    {
        return ScannerCategory::Infrastructure->value;
    }

    public function severity(): string
    {
        return 'high';
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $host = parse_url($project->target_url, PHP_URL_HOST) ?? $project->target_url;

        try {
            $context = stream_context_create(['ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ]]);

            $client = @stream_socket_client(
                "ssl://{$host}:443",
                $errno,
                $errstr,
                $this->timeout,
                STREAM_CLIENT_CONNECT,
                $context
            );

            if (!$client) {
                $results->add($this->createResult(
                    'info',
                    'SSL not available on port 443',
                    "Could not connect to {$host}:443 via SSL: {$errstr}"
                ));
                return $results;
            }

            $params = stream_context_get_params($client);
            fclose($client);

            if (isset($params['options']['ssl']['peer_certificate'])) {
                $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);

                if ($cert) {
                    $validFrom = $cert['validFrom_time_t'] ?? 0;
                    $validTo = $cert['validTo_time_t'] ?? 0;
                    $now = time();
                    $daysUntilExpiry = (int)(($validTo - $now) / 86400);

                    $results->add($this->createResult(
                        $daysUntilExpiry < 30 ? 'high' : ($daysUntilExpiry < 90 ? 'medium' : 'info'),
                        'SSL certificate found',
                        sprintf(
                            'Certificate for %s: issued by %s, expires in %d days',
                            $host,
                            $cert['issuer']['CN'] ?? 'Unknown',
                            $daysUntilExpiry
                        ),
                        [
                            'subject' => $cert['subject'] ?? [],
                            'issuer' => $cert['issuer'] ?? [],
                            'valid_from' => date('Y-m-d', $validFrom),
                            'valid_to' => date('Y-m-d', $validTo),
                            'days_until_expiry' => $daysUntilExpiry,
                            'signature_algorithm' => $cert['signatureTypeSN'] ?? 'unknown',
                        ]
                    ));

                    if ($daysUntilExpiry < 30) {
                        $results->add($this->createResult(
                            'high',
                            'SSL certificate expiring soon',
                            "SSL certificate expires in {$daysUntilExpiry} days",
                            ['expiry_date' => date('Y-m-d', $validTo)]
                        ));
                    }
                }
            }
        } catch (\Throwable $e) {
            $results->add($this->createResult(
                'info',
                'SSL scan failed',
                "Could not analyze SSL: {$e->getMessage()}"
            ));
        }

        return $results;
    }

    public function dependencies(): array
    {
        return ['port_scanner'];
    }
}
