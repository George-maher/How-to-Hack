<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class SecurityHeadersScanner extends BaseScanner
{
    private array $securityHeaders = [];

    public function __construct(\App\Security\Http\SafeHttpClient $http)
    {
        parent::__construct($http);
        $this->securityHeaders = [
            'Strict-Transport-Security' => [
                'severity' => 'medium',
                'description' => 'HTTP Strict Transport Security (HSTS)',
                'recommendation' => 'Set Strict-Transport-Security header with a minimum age of 31536000 seconds (1 year) and includeSubDomains directive.',
            ],
            'Content-Security-Policy' => [
                'severity' => 'high',
                'description' => 'Content Security Policy (CSP)',
                'recommendation' => 'Implement a Content-Security-Policy header to prevent XSS and data injection attacks. Start with a restrictive policy and relax as needed.',
            ],
            'X-Frame-Options' => [
                'severity' => 'medium',
                'description' => 'Clickjacking Protection',
                'recommendation' => 'Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking attacks.',
            ],
            'X-Content-Type-Options' => [
                'severity' => 'medium',
                'description' => 'MIME Type Sniffing Protection',
                'recommendation' => 'Set X-Content-Type-Options: nosniff to prevent MIME type sniffing.',
            ],
            'Referrer-Policy' => [
                'severity' => 'low',
                'description' => 'Referrer Policy',
                'recommendation' => 'Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer to control referrer information leakage.',
            ],
            'Permissions-Policy' => [
                'severity' => 'low',
                'description' => 'Permissions Policy',
                'recommendation' => 'Set Permissions-Policy header to restrict browser features (geolocation, camera, microphone, etc.).',
            ],
            'X-XSS-Protection' => [
                'severity' => 'low',
                'description' => 'XSS Protection',
                'recommendation' => 'Set X-XSS-Protection: 1; mode=block to enable browser XSS filtering.',
            ],
        ];
    }

    public function name(): string
    {
        return 'security_headers';
    }

    public function description(): string
    {
        return 'Analyzes HTTP security headers including HSTS, CSP, X-Frame-Options, and more';
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
            $flatHeaders = [];
            foreach ($headers as $key => $values) {
                $flatHeaders[strtolower($key)] = is_array($values) ? $values[0] : $values;
            }

            foreach ($this->securityHeaders as $header => $config) {
                $headerLower = strtolower($header);
                $value = $flatHeaders[$headerLower] ?? null;

                if ($value === null) {
                    $results->add($this->createResult(
                        $config['severity'],
                        "Missing security header: {$header}",
                        "The '{$header}' ({$config['description']}) is not present in HTTP response headers",
                        [
                            'missing_header' => $header,
                            'severity' => $config['severity'],
                            'recommendation' => $config['recommendation'],
                        ]
                    ));
                }
            }

            $this->analyzeCookieFlags($flatHeaders, $results);

        } catch (\Throwable $e) {
            $results->add($this->createResult(
                'info',
                'Security header analysis failed',
                "Could not analyze security headers: {$e->getMessage()}"
            ));
        }

        return $results;
    }

    private function analyzeCookieFlags(array $headers, ScanResultCollection $results): void
    {
        $setCookie = $headers['set-cookie'] ?? null;
        if (!$setCookie) {
            return;
        }

        $cookies = is_array($setCookie) ? $setCookie : [$setCookie];

        foreach ($cookies as $cookieHeader) {
            $cookieName = strstr($cookieHeader, '=', true) ?: $cookieHeader;

            if (!preg_match('/;\s*secure\s*(;|$)/i', $cookieHeader)) {
                $results->add($this->createResult(
                    'medium',
                    "Cookie missing Secure flag: {$cookieName}",
                    "The '{$cookieName}' cookie is set without the Secure flag, allowing transmission over unencrypted connections",
                    [
                        'cookie' => $cookieName,
                        'missing_flag' => 'Secure',
                        'recommendation' => 'Add the Secure flag to all cookies to ensure they are only sent over HTTPS.',
                    ]
                ));
            }

            if (!preg_match('/;\s*httponly\s*(;|$)/i', $cookieHeader)) {
                $results->add($this->createResult(
                    'medium',
                    "Cookie missing HttpOnly flag: {$cookieName}",
                    "The '{$cookieName}' cookie is set without the HttpOnly flag, making it accessible to JavaScript",
                    [
                        'cookie' => $cookieName,
                        'missing_flag' => 'HttpOnly',
                        'recommendation' => 'Add the HttpOnly flag to cookies that do not require JavaScript access to mitigate XSS-based cookie theft.',
                    ]
                ));
            }

            if (!preg_match('/;\s*samesite=(lax|strict|none)\s*(;|$)/i', $cookieHeader)) {
                $results->add($this->createResult(
                    'low',
                    "Cookie missing SameSite attribute: {$cookieName}",
                    "The '{$cookieName}' cookie is set without the SameSite attribute",
                    [
                        'cookie' => $cookieName,
                        'missing_attribute' => 'SameSite',
                        'recommendation' => 'Set SameSite=Lax or SameSite=Strict to prevent CSRF attacks.',
                    ]
                ));
            }
        }
    }

    public function dependencies(): array
    {
        return ['http_analyzer'];
    }
}
