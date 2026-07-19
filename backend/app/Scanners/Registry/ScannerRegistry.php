<?php

namespace App\Scanners\Registry;

use App\Contracts\ScannerInterface;
use App\Exceptions\ScannerNotFoundException;
use Illuminate\Support\Collection;

class ScannerRegistry
{
    private Collection $scanners;

    public function __construct(array $scannerClasses = [])
    {
        $this->scanners = collect();
        foreach ($scannerClasses as $class) {
            $this->register(app($class));
        }
    }

    public function register(ScannerInterface $scanner): void
    {
        $this->scanners->put($scanner->name(), $scanner);
    }

    public function get(string $name): ScannerInterface
    {
        if (!$this->scanners->has($name)) {
            throw new ScannerNotFoundException($name);
        }
        return $this->scanners->get($name);
    }

    public function all(): Collection
    {
        return $this->scanners;
    }

    public function getByCategory(string $category): Collection
    {
        return $this->scanners->filter(
            fn(ScannerInterface $s) => $s->category() === $category
        );
    }

    public function getUnused(array $usedScanners): Collection
    {
        return $this->scanners->reject(
            fn(ScannerInterface $s) => in_array($s->name(), $usedScanners)
        );
    }

    public function getRecommended(array $context): Collection
    {
        return $this->scanners->filter(
            fn(ScannerInterface $s) => $this->isRecommended($s, $context)
        );
    }

    private function isRecommended(ScannerInterface $scanner, array $context): bool
    {
        $deps = $scanner->dependencies();
        if (empty($deps)) {
            return true;
        }
        foreach ($deps as $dep) {
            if (!in_array($dep, $context['completed_scanners'] ?? [])) {
                return false;
            }
        }
        return true;
    }

    public function count(): int
    {
        return $this->scanners->count();
    }
}
