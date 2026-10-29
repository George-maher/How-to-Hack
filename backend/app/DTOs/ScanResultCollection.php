<?php

declare(strict_types=1);

namespace App\DTOs;

use App\Enums\SeverityLevel;

/**
 * A list of findings. Carries no notion of success: that lives in
 * ScannerExecutionResult, so an empty list can never masquerade as a clean scan.
 */
final class ScanResultCollection
{
    /** @var list<ScanResult> */
    private array $items;

    /**
     * @param  iterable<ScanResult>  $items
     */
    public function __construct(iterable $items = [])
    {
        $this->items = [];

        foreach ($items as $item) {
            if ($item instanceof ScanResult) {
                $this->items[] = $item;
            }
        }
    }

    public function add(ScanResult $result): void
    {
        $this->items[] = $result;
    }

    /** @return list<ScanResult> */
    public function all(): array
    {
        return $this->items;
    }

    /** @return list<array<string, mixed>> */
    public function toArray(): array
    {
        return array_map(static fn (ScanResult $r) => $r->toArray(), $this->items);
    }

    public function count(): int
    {
        return count($this->items);
    }

    public function isEmpty(): bool
    {
        return $this->items === [];
    }

    public function highValue(): self
    {
        return new self(array_filter(
            $this->items,
            static fn (ScanResult $r) => $r->severity->weight() >= SeverityLevel::High->weight(),
        ));
    }

    public function merge(self $other): self
    {
        return new self(array_merge($this->items, $other->items));
    }
}
