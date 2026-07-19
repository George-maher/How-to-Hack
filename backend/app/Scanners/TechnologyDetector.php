<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;
use Illuminate\Support\Facades\Http;

class TechnologyDetector extends BaseScanner
{
    private array $techPatterns = [
        'Laravel' => ['headers' => ['x-powered-by' => '/laravel/i']],
        'PHP' => ['headers' => ['x-powered-by' => '/php/i'], 'body' => ['/php/i']],
        'WordPress' => ['body' => ['/wp-content/', '/wp-includes/', '/wp-json/']],
        'Drupal' => ['body' => ['/drupal/', '/sites\/default/', '/drupal\.js/']],
        'Joomla' => ['body' => ['/joomla/', '/com_content/', '/mod_random_image/']],
        'nginx' => ['headers' => ['server' => '/nginx/i']],
        'Apache' => ['headers' => ['server' => '/apache/i']],
        'IIS' => ['headers' => ['server' => '/iis/i', 'x-powered-by' => '/asp\.net/i']],
        'React' => ['body' => ['/react\.js/', '/react\.min\.js/', '/_next\/static/']],
        'Vue.js' => ['body' => ['/vue\.js/', '/vue\.min\.js/', '/__vue__/']],
        'Angular' => ['body' => ['/angular\.js/', '/angular\.min\.js/', '/ng-app/']],
        'jQuery' => ['body' => ['/jquery\.js/', '/jquery\.min\.js/']],
        'Bootstrap' => ['body' => ['/bootstrap\.css/', '/bootstrap\.min\.css/', '/bootstrap\.js/']],
        'Tailwind CSS' => ['body' => ['/tailwind/', '/tailwindcss/i']],
        'Alpine.js' => ['body' => ['/alpine\.js/', '/alpine\.min\.js/']],
        'Livewire' => ['body' => ['/livewire/', '/livewire/i']],
        'MySQL' => ['headers' => ['x-powered-by' => '/mysql/i']],
        'Redis' => ['headers' => ['x-powered-by' => '/redis/i']],
        'Cloudflare' => ['headers' => ['server' => '/cloudflare/i'], 'body' => ['/cloudflare/i']],
        'Google Analytics' => ['body' => ['/google-analytics\.com/', '/googletagmanager\.com/']],
    ];

    public function name(): string
    {
        return 'technology_detector';
    }

    public function description(): string
    {
        return 'Detects web technologies used by the target';
    }

    public function category(): string
    {
        return ScannerCategory::Reconnaissance->value;
    }

    public function severity(): string
    {
        return 'info';
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();

        try {
            $response = Http::timeout($this->timeout)->get($project->target_url);
            $headers = $response->headers();
            $body = $response->body();
            $detected = [];

            foreach ($this->techPatterns as $tech => $patterns) {
                if ($this->matchesPatterns($headers, $body, $patterns)) {
                    $detected[] = $tech;
                }
            }

            if (!empty($detected)) {
                $results->add($this->createResult(
                    'info',
                    'Technologies detected',
                    sprintf('Detected %d technology/ies: %s', count($detected), implode(', ', $detected)),
                    ['technologies' => $detected]
                ));

                $vulnerableTechs = $this->getVulnerableTechnologies($detected);
                foreach ($vulnerableTechs as $tech) {
                    $results->add($this->createResult(
                        'medium',
                        "Potentially vulnerable technology: {$tech}",
                        "{$tech} may have known vulnerabilities. Consider checking for updates.",
                        ['technology' => $tech]
                    ));
                }
            } else {
                $results->add($this->createResult(
                    'info',
                    'No specific technologies detected',
                    'Could not identify specific web technologies'
                ));
            }
        } catch (\Throwable $e) {
            $results->add($this->createResult(
                'info',
                'Technology detection failed',
                "Could not analyze target: {$e->getMessage()}"
            ));
        }

        return $results;
    }

    private function matchesPatterns(array $headers, string $body, array $patterns): bool
    {
        foreach ($patterns as $type => $patternsList) {
            if ($type === 'headers') {
                foreach ($patternsList as $header => $pattern) {
                    $headerKey = strtolower($header);
                    if (isset($headers[$headerKey])) {
                        $value = is_array($headers[$headerKey]) ? $headers[$headerKey][0] : $headers[$headerKey];
                        if (preg_match($pattern, $value)) {
                            return true;
                        }
                    }
                }
            }
            if ($type === 'body') {
                foreach ($patternsList as $pattern) {
                    if (preg_match($pattern, $body)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private function getVulnerableTechnologies(array $detected): array
    {
        $vulnerable = ['WordPress', 'Drupal', 'Joomla'];
        return array_intersect($detected, $vulnerable);
    }
}
