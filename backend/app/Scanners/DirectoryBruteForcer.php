<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;
use Illuminate\Support\Facades\Http;

class DirectoryBruteForcer extends BaseScanner
{
    private array $commonPaths = [
        '/admin', '/login', '/wp-admin', '/administrator',
        '/backup', '/.git', '/.env', '/config',
        '/phpinfo.php', '/info.php', '/test.php',
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
        '/api', '/v1', '/v2', '/graphql',
        '/.well-known/security.txt', '/.well-known/',
        '/swagger', '/docs', '/api-docs',
        '/console', '/panel', '/cpanel',
        '/server-status', '/server-info',
        '/wp-json', '/xmlrpc.php',
        '/.htaccess', '/.htpasswd',
        '/database', '/sql', '/dump',
        '/tmp', '/temp', '/logs', '/debug',
    ];

    public function name(): string
    {
        return 'directory_brute_forcer';
    }

    public function description(): string
    {
        return 'Enumerates common directories and files on the web server';
    }

    public function category(): string
    {
        return ScannerCategory::WebApplication->value;
    }

    public function severity(): string
    {
        return 'high';
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $baseUrl = rtrim($project->target_url, '/');
        $filterStatus = $context['filter_status'] ?? null;

        foreach ($this->commonPaths as $path) {
            try {
                $url = $baseUrl . $path;
                $response = Http::timeout(max(2, $this->timeout / count($this->commonPaths)))
                    ->withOptions(['allow_redirects' => false])
                    ->head($url);

                $status = $response->status();

                $storeResult = [
                    'path' => $path,
                    'url' => $url,
                    'status_code' => $status,
                    'method' => 'HEAD',
                ];

                if ($filterStatus !== null) {
                    if ($status !== (int) $filterStatus) {
                        continue;
                    }
                }

                if ($status === 200) {
                    $severity = $this->getPathSeverity($path, $status);
                    $results->add($this->createResult(
                        $severity,
                        "Accessible path: {$path}",
                        "Found accessible path '{$path}' (HTTP {$status})",
                        $storeResult
                    ));
                }
            } catch (\Throwable) {
                continue;
            }
        }

        if ($results->count() === 0) {
            $results->add($this->createResult(
                'info',
                'No common paths discovered',
                'No common directories or files were found accessible'
            ));
        }

        return $results;
    }

    public function getHttp200Endpoints(Project $project): ScanResultCollection
    {
        return $this->scan($project, ['filter_status' => 200]);
    }

    private function getPathSeverity(string $path, int $status): string
    {
        $sensitive = ['/.git', '/.env', '/backup', '/database', '/sql', '/dump', '/.htaccess', '/.htpasswd'];
        $admin = ['/admin', '/login', '/wp-admin', '/administrator', '/panel', '/cpanel', '/console'];

        if (in_array($path, $sensitive)) {
            return 'critical';
        }
        if (in_array($path, $admin)) {
            return 'high';
        }
        if ($status === 401 || $status === 403) {
            return 'medium';
        }
        return 'low';
    }
}
