<?php

namespace App\Services\Ai\Providers;

use App\Contracts\AiProviderInterface;
use App\DTOs\ScanContext;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class OpenRouterProvider implements AiProviderInterface
{
    private string $apiKey;
    private string $baseUrl;
    private string $model;
    private float $temperature;
    private int $maxTokens;

    public function __construct()
    {
        $config = config('ai-agent.providers.openrouter');
        $this->apiKey = $config['api_key'] ?? '';
        $this->baseUrl = $config['base_url'] ?? 'https://openrouter.ai/api/v1';
        $this->model = $config['model'] ?? 'openai/gpt-4o';
        $this->temperature = (float) ($config['temperature'] ?? 0.3);
        $this->maxTokens = (int) ($config['max_tokens'] ?? 2000);
    }

    public function decideNextScanner(ScanContext $context): string
    {
        if (empty($this->apiKey)) {
            return $this->fallbackDecision($context);
        }

        try {
            $response = Http::withHeaders([
                'Authorization' => "Bearer {$this->apiKey}",
                'HTTP-Referer' => config('app.url', 'http://localhost'),
            ])->timeout(30)->post("{$this->baseUrl}/chat/completions", [
                'model' => $this->model,
                'temperature' => $this->temperature,
                'max_tokens' => $this->maxTokens,
                'messages' => [
                    ['role' => 'system', 'content' => $this->getSystemPrompt()],
                    ['role' => 'user', 'content' => $this->buildPrompt($context)],
                ],
            ]);

            $result = $response->json();
            $decision = trim($result['choices'][0]['message']['content'] ?? '');
            Log::info('OpenRouter AI decision received', ['decision' => $decision]);
            return $decision;
        } catch (\Throwable $e) {
            Log::warning('OpenRouter AI provider failed, using fallback', ['error' => $e->getMessage()]);
            return $this->fallbackDecision($context);
        }
    }

    public function analyzeResults(array $results, array $reasoningChain): string
    {
        return 'OpenRouter analysis unavailable';
    }

    public function shouldStop(array $completedScanners, array $results): bool
    {
        $highValue = 0;
        foreach ($results as $findings) {
            foreach ($findings as $finding) {
                if (in_array($finding['severity'] ?? '', ['high', 'critical'])) {
                    $highValue++;
                }
            }
        }
        return $highValue === 0 && count($completedScanners) >= 4;
    }

    private function getSystemPrompt(): string
    {
        $scannerList = $this->buildScannerList();
        return <<<PROMPT
You are an intelligent security scan planner. Available scanners:
{$scannerList}

Return only the scanner name or "STOP".
PROMPT;
    }

    private function buildScannerList(): string
    {
        $lines = [];
        foreach (config('scanners.registry', []) as $class) {
            $scanner = app($class);
            $deps = $scanner->dependencies();
            $depInfo = !empty($deps) ? ' (needs ' . implode(', ', $deps) . ')' : '';
            $lines[] = "- {$scanner->name()}: {$scanner->description()} ({$scanner->category()}){$depInfo}";
        }
        return implode("\n", $lines);
    }

    private function buildPrompt(ScanContext $context): string
    {
        $data = $context->toArray();
        return sprintf(
            "Target: %s\nCompleted: [%s]\nResults: %s\nReasoning: %s\n\nNext scanner?",
            $data['target'],
            implode(', ', $data['completed_scanners']),
            json_encode($data['results_summary']),
            implode('; ', $data['reasoning_history'])
        );
    }

    private function fallbackDecision(ScanContext $context): string
    {
        $registry = app(\App\Scanners\Registry\ScannerRegistry::class);
        $available = $registry->getRecommended($context->toArray());

        foreach ($available as $scanner) {
            if (!in_array($scanner->name(), $context->completedScanners)) {
                return $scanner->name();
            }
        }

        return 'STOP';
    }
}
