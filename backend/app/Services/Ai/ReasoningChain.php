<?php

namespace App\Services\Ai;

use Illuminate\Support\Collection;

class ReasoningChain
{
    private Collection $entries;

    public function __construct(array $entries = [])
    {
        $this->entries = collect($entries);
    }

    public function add(string $scannerName, string $reason, array $context = []): void
    {
        $this->entries->push([
            'timestamp' => now()->toIso8601String(),
            'scanner' => $scannerName,
            'reason' => $reason,
            'context' => $context,
        ]);
    }

    public function all(): array
    {
        return $this->entries->all();
    }

    public function toArray(): array
    {
        return $this->all();
    }

    public function count(): int
    {
        return $this->entries->count();
    }

    public function last(): ?array
    {
        return $this->entries->last();
    }

    public function decisions(): array
    {
        return $this->entries->pluck('scanner')->all();
    }

    public function getUnusedScanners(array $allScanners): array
    {
        return array_diff($allScanners, $this->decisions());
    }

    public function hasDuplicates(): bool
    {
        $decisions = $this->decisions();
        return count($decisions) !== count(array_unique($decisions));
    }

    public function summary(): string
    {
        $parts = [];
        foreach ($this->entries as $entry) {
            $parts[] = "  - {$entry['scanner']}: {$entry['reason']}";
        }
        return implode("\n", $parts);
    }
}
