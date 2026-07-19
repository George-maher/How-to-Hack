<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;
use Illuminate\Support\Facades\Http;

class ApiAssessmentScanner extends BaseScanner
{
    private array $apiPaths = [
        '/api', '/api/v1', '/api/v2', '/api/v3',
        '/swagger', '/swagger.json', '/swagger.yaml', '/swagger.yml',
        '/api-docs', '/docs', '/openapi.json', '/openapi.yaml',
        '/graphql', '/graphiql', '/playground',
        '/.well-known/openid-configuration',
        '/oauth', '/oauth2', '/token', '/auth',
        '/rest', '/soap', '/wsdl', '/api/health',
    ];

    private array $jwtHeaders = [
        'Authorization',
        'X-Authorization',
        'X-Api-Key',
        'X-Auth-Token',
        'Bearer',
    ];

    public function name(): string
    {
        return 'api_assessment';
    }

    public function description(): string
    {
        return 'API security assessment - endpoint discovery, JWT inspection, and security header analysis';
    }

    public function category(): string
    {
        return ScannerCategory::ApiAssessment->value;
    }

    public function severity(): string
    {
        return 'high';
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();

        try {
            $baseUrl = rtrim($project->target_url, '/');

            $this->discoverApiEndpoints($baseUrl, $results);
            $this->analyzeApiSpecifications($baseUrl, $results);
            $this->analyzeApiSecurityHeaders($baseUrl, $results);
            $this->analyzeJwtTokens($baseUrl, $results);

            if ($results->count() === 0) {
                $results->add($this->createResult(
                    'info',
                    'No API endpoints discovered',
                    'API assessment did not discover common API endpoints'
                ));
            }

        } catch (\Throwable $e) {
            $results->add($this->createResult(
                'info',
                'API assessment incomplete',
                "API assessment could not be completed: {$e->getMessage()}"
            ));
        }

        return $results;
    }

    private function discoverApiEndpoints(string $baseUrl, ScanResultCollection $results): void
    {
        $discovered = [];

        foreach ($this->apiPaths as $path) {
            try {
                $url = $baseUrl . $path;
                $response = Http::timeout(5)
                    ->withOptions(['allow_redirects' => false])
                    ->head($url);

                $status = $response->status();
                $contentType = $response->header('Content-Type', '');

                if ($status >= 200 && $status < 500) {
                    $entry = [
                        'endpoint' => $url,
                        'status' => $status,
                        'content_type' => $contentType,
                    ];
                    $discovered[] = $entry;
                }
            } catch (\Throwable) {
                continue;
            }
        }

        if (!empty($discovered)) {
            $results->add($this->createResult(
                'medium',
                'API endpoints discovered',
                sprintf('Found %d API endpoint(s)', count($discovered)),
                ['api_endpoints' => $discovered]
            ));

            $openEndpoints = array_filter($discovered, fn($e) => $e['status'] === 200);
            if (!empty($openEndpoints)) {
                $results->add($this->createResult(
                    'high',
                    'Publicly accessible API endpoints',
                    sprintf('Found %d API endpoint(s) returning HTTP 200', count($openEndpoints)),
                    ['open_endpoints' => $openEndpoints]
                ));
            }
        }
    }

    private function analyzeApiSpecifications(string $baseUrl, ScanResultCollection $results): void
    {
        $specPaths = [
            '/swagger.json' => 'Swagger/OpenAPI JSON',
            '/swagger.yaml' => 'Swagger/OpenAPI YAML',
            '/swagger.yml' => 'Swagger/OpenAPI YAML',
            '/openapi.json' => 'OpenAPI JSON',
            '/api-docs' => 'API Documentation',
            '/docs' => 'API Documentation',
        ];

        foreach ($specPaths as $path => $type) {
            try {
                $url = $baseUrl . $path;
                $response = Http::timeout(5)->get($url);

                if ($response->successful()) {
                    $contentType = $response->header('Content-Type', '');
                    $body = $response->body();

                    if (str_contains($contentType, 'json') || str_contains($contentType, 'yaml') || str_contains($contentType, 'yml')) {
                        $results->add($this->createResult(
                            'high',
                            "API specification exposed: {$type}",
                            "API specification found at {$url}. This may expose internal API structure",
                            [
                                'url' => $url,
                                'type' => $type,
                                'content_snippet' => substr($body, 0, 500),
                                'remediation' => 'Restrict access to API documentation in production. Implement authentication for API docs.',
                            ]
                        ));

                        $this->analyzeOpenApiSpec($body, $url, $results);
                    }
                }
            } catch (\Throwable) {
                continue;
            }
        }
    }

    private function analyzeOpenApiSpec(string $body, string $url, ScanResultCollection $results): void
    {
        $spec = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return;
        }

        if (isset($spec['info']['version'])) {
            $results->add($this->createResult(
                'info',
                'API version exposed',
                "API version: {$spec['info']['version']}",
                ['version' => $spec['info']['version']]
            ));
        }

        if (isset($spec['paths'])) {
            $totalEndpoints = 0;
            $unauthenticated = 0;

            foreach ($spec['paths'] as $path => $methods) {
                if (is_array($methods)) {
                    foreach ($methods as $method => $details) {
                        if (!in_array($method, ['get', 'post', 'put', 'delete', 'patch'])) {
                            continue;
                        }
                        $totalEndpoints++;

                        if (!isset($details['security']) || empty($details['security'])) {
                            $unauthenticated++;
                        }
                    }
                }
            }

            $results->add($this->createResult(
                'info',
                'OpenAPI endpoints cataloged',
                sprintf('API specification defines %d endpoint(s), %d without explicit security', $totalEndpoints, $unauthenticated),
                [
                    'total_endpoints' => $totalEndpoints,
                    'unauthenticated_endpoints' => $unauthenticated,
                ]
            ));

            if ($unauthenticated > 0) {
                $results->add($this->createResult(
                    'high',
                    'API endpoints without authentication',
                    sprintf('%d of %d API endpoints do not specify authentication requirements', $unauthenticated, $totalEndpoints),
                    [
                        'unauthenticated_count' => $unauthenticated,
                        'remediation' => 'Implement authentication for all API endpoints. Use OAuth 2.0 or API keys.',
                    ]
                ));
            }
        }
    }

    private function analyzeApiSecurityHeaders(string $baseUrl, ScanResultCollection $results): void
    {
        try {
            $response = Http::timeout($this->timeout)
                ->withOptions(['allow_redirects' => true])
                ->get($baseUrl);

            $headers = $response->headers();

            $checks = [
                'content-security-policy' => ['desc' => 'Content Security Policy', 'severity' => 'high'],
                'strict-transport-security' => ['desc' => 'HTTP Strict Transport Security', 'severity' => 'medium'],
                'x-content-type-options' => ['desc' => 'X-Content-Type-Options', 'severity' => 'medium'],
                'x-frame-options' => ['desc' => 'X-Frame-Options', 'severity' => 'medium'],
                'cache-control' => ['desc' => 'Cache-Control for sensitive data', 'severity' => 'medium'],
            ];

            foreach ($checks as $header => $info) {
                if (!isset($headers[$header])) {
                    $results->add($this->createResult(
                        $info['severity'],
                        "Missing API security header: {$info['desc']}",
                        "The '{$header}' header is not set in API response",
                        ['missing_header' => $header]
                    ));
                }
            }

            if (isset($headers['access-control-allow-origin'])) {
                $origin = implode(', ', $headers['access-control-allow-origin']);
                if ($origin === '*' || $origin === 'null') {
                    $results->add($this->createResult(
                        'high',
                        'Permissive CORS policy detected',
                        "API allows all origins via CORS: {$origin}",
                        ['cors_origin' => $origin]
                    ));
                }
            }

        } catch (\Throwable $e) {
            $results->add($this->createResult(
                'info',
                'API security header analysis failed',
                "Could not analyze API security headers: {$e->getMessage()}"
            ));
        }
    }

    private function analyzeJwtTokens(string $baseUrl, ScanResultCollection $results): void
    {
        try {
            $response = Http::timeout($this->timeout)
                ->withOptions(['allow_redirects' => true])
                ->get($baseUrl);

            $body = $response->body();

            preg_match_all('/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/', $body, $jwtMatches);

            if (!empty($jwtMatches[0])) {
                $results->add($this->createResult(
                    'high',
                    'JWT tokens found in response',
                    sprintf('Found %d potential JWT token(s) in response body', count($jwtMatches[0])),
                    [
                        'jwt_count' => count($jwtMatches[0]),
                        'remediation' => 'Ensure JWT tokens are not exposed in client-side responses. Implement proper token lifecycle management.',
                    ]
                ));
            }

            $responseHeaders = $response->headers();
            foreach ($this->jwtHeaders as $header) {
                $headerKey = strtolower($header);
                if (isset($responseHeaders[$headerKey])) {
                    $value = implode(', ', $responseHeaders[$headerKey]);
                    if (str_starts_with(strtolower($value), 'bearer ')) {
                        $results->add($this->createResult(
                            'info',
                            'Bearer authentication detected',
                            "API uses Bearer token authentication via {$header} header",
                            ['auth_header' => $header]
                        ));
                    }
                }
            }

        } catch (\Throwable) {
            // Silently handle JWT analysis failures
        }
    }

    public function dependencies(): array
    {
        return ['http_analyzer', 'directory_brute_forcer'];
    }
}
