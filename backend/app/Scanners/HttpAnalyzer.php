<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class HttpAnalyzer extends BaseScanner
{
    public function name(): string
    {
        return 'http_analyzer';
    }

    public function description(): string
    {
        return 'Analyzes HTTP security headers and configuration';
    }

    public function category(): string
    {
        return ScannerCategory::WebApplication->value;
    }

    public function severity(): string
    {
        return 'medium';
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();

        try {
            $response = $this->http->guarded($this->timeout)
                ->withOptions(['allow_redirects' => true])
                ->get($project->target_url);

            $headers = $response->headers();

            $this->analyzeSecurityHeaders($headers, $results);
            $this->analyzeServerInfo($headers, $results, $project->target_url);
            $this->analyzeCookies($headers, $results);

            $results->add($this->createResult(
                'info',
                'HTTP response analysis',
                sprintf(
                    'Target responded with HTTP %d, %d headers, %d bytes',
                    $response->status(),
                    count($headers),
                    strlen($response->body())
                ),
                [
                    'status_code' => $response->status(),
                    'content_type' => $headers['content-type'][0] ?? 'unknown',
                    'content_length' => strlen($response->body()),
                ]
            ));
        } catch (\Throwable $e) {
            $results->add($this->createResult(
                'info',
                'HTTP analysis failed',
                "Could not connect to target: {$e->getMessage()}"
            ));
        }

        return $results;
    }

    private function analyzeSecurityHeaders(array $headers, ScanResultCollection $results): void
    {
        $securityHeaders = [
            'Strict-Transport-Security' => ['desc' => 'HTTP Strict Transport Security (HSTS)', 'severity' => 'medium'],
            'Content-Security-Policy' => ['desc' => 'Content Security Policy (CSP)', 'severity' => 'high'],
            'X-Frame-Options' => ['desc' => 'Clickjacking protection', 'severity' => 'medium'],
            'X-Content-Type-Options' => ['desc' => 'MIME type sniffing protection', 'severity' => 'medium'],
            'Referrer-Policy' => ['desc' => 'Referrer Policy', 'severity' => 'low'],
            'Permissions-Policy' => ['desc' => 'Permissions Policy', 'severity' => 'low'],
            'X-XSS-Protection' => ['desc' => 'XSS Protection', 'severity' => 'medium'],
        ];

        foreach ($securityHeaders as $header => $info) {
            $headerKey = strtolower($header);
            if (!isset($headers[$headerKey])) {
                $results->add($this->createResult(
                    $info['severity'],
                    "Missing security header: {$header}",
                    "The {$info['desc']} header is not set on the target",
                    ['missing_header' => $header]
                ));
            }
        }
    }

    private function analyzeServerInfo(array $headers, ScanResultCollection $results, string $url): void
    {
        $infoHeaders = ['server', 'x-powered-by', 'x-aspnet-version'];

        foreach ($infoHeaders as $header) {
            if (isset($headers[$header])) {
                $value = is_array($headers[$header]) ? $headers[$header][0] : $headers[$header];
                $results->add($this->createResult(
                    'low',
                    "Information disclosure: {$header}",
                    "Server header '{$header}' reveals: {$value}",
                    ['header' => $header, 'value' => $value]
                ));
            }
        }
    }

    private function analyzeCookies(array $headers, ScanResultCollection $results): void
    {
        if (!isset($headers['set-cookie'])) {
            return;
        }

        $cookies = $headers['set-cookie'];
        foreach ((array) $cookies as $cookieHeader) {
            if (!preg_match('/;\s*secure\s*(;|$)/i', $cookieHeader)) {
                $results->add($this->createResult(
                    'medium',
                    'Cookie missing Secure flag',
                    "Cookie is set without the Secure flag: " . strstr($cookieHeader, ';', true),
                    ['cookie' => $cookieHeader]
                ));
            }
            if (!preg_match('/;\s*httponly\s*(;|$)/i', $cookieHeader)) {
                $results->add($this->createResult(
                    'medium',
                    'Cookie missing HttpOnly flag',
                    "Cookie is set without the HttpOnly flag: " . strstr($cookieHeader, ';', true),
                    ['cookie' => $cookieHeader]
                ));
            }
            if (!preg_match('/;\s*samesite=(lax|strict|none)\s*(;|$)/i', $cookieHeader)) {
                $results->add($this->createResult(
                    'low',
                    'Cookie missing SameSite attribute',
                    "Cookie is set without SameSite attribute: " . strstr($cookieHeader, ';', true),
                    ['cookie' => $cookieHeader]
                ));
            }
        }
    }

    public function dependencies(): array
    {
        return ['port_scanner'];
    }
}
