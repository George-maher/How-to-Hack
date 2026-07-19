<?php

namespace App\DTOs;

use App\Enums\SeverityLevel;
use Illuminate\Support\Collection;

class ScanResultCollection
{
    private Collection $items;

    public function __construct(array $items = [])
    {
        $this->items = collect($items);
    }

    public function add(ScanResult $result): void
    {
        $this->items->push($result);
    }

    public function all(): array
    {
        return $this->items->all();
    }

    public function toArray(): array
    {
        return $this->items->map(fn(ScanResult $r) => $r->toArray())->all();
    }

    public function count(): int
    {
        return $this->items->count();
    }

    public function highValue(): self
    {
        return new self(
            $this->items->filter(fn(ScanResult $r) => $r->severity->weight() >= SeverityLevel::High->weight())->all()
        );
    }

    public function merge(self $other): self
    {
        return new self(array_merge($this->items->all(), $other->items->all()));
    }
}
