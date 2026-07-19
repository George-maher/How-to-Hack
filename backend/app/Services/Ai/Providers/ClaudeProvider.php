<?php

namespace App\Services\Ai\Providers;

use App\Contracts\AiProviderInterface;
use App\DTOs\ScanContext;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ClaudeProvider implements AiProviderInterface
{
    private string $apiKey;
    private string $model;
    private int $maxTokens;

    public function __construct()
    {
        $config = config('ai-agent.providers.claude');
        $this->apiKey = $config['api_key'] ?? '';
        $this->model = $config['model'] ?? 'claude-3-opus-20240229';
        $this->maxTokens = (int) ($config['max_tokens'] ?? 2000);
    }

    public function decideNextScanner(ScanContext $context): string
    {
        if (empty($this->apiKey)) {
            return $this->fallbackDecision($context);
        }

        try {
            $response = Http::withHeaders([
                'x-api-key' => $this->apiKey,
                'anthropic-version' => '2023-06-01',
            ])->timeout(30)->post('https://api.anthropic.com/v1/messages', [
                'model' => $this->model,
                'max_tokens' => $this->maxTokens,
                'system' => $this->getSystemPrompt(),
                'messages' => [
                    ['role' => 'user', 'content' => $this->buildPrompt($context)],
                ],
            ]);

            $result = $response->json();
            $content = $result['content'][0]['text'] ?? '';
            $decision = trim($content);
            Log::info('Claude AI decision received', ['decision' => $decision]);
            return $decision;
        } catch (\Throwable $e) {
            Log::warning('Claude AI provider failed, using fallback', ['error' => $e->getMessage()]);
            return $this->fallbackDecision($context);
        }
    }

    public function analyzeResults(array $results, array $reasoningChain): string
    {
        return 'Claude analysis unavailable';
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
        return json_encode([
            'target' => $data['target'],
            'completed' => $data['completed_scanners'],
            'results' => $data['results_summary'],
            'reasoning' => $data['reasoning_history'],
        ]);
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
