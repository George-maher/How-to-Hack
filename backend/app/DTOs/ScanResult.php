<?php

namespace App\DTOs;

use App\Enums\SeverityLevel;

class ScanResult
{
    public function __construct(
        public readonly string $scannerName,
        public readonly SeverityLevel $severity,
        public readonly string $title,
        public readonly string $description,
        public readonly array $details = [],
        public readonly ?string $filePath = null,
    ) {}

    public function toArray(): array
    {
        return [
            'scanner_name' => $this->scannerName,
            'severity' => $this->severity->value,
            'title' => $this->title,
            'description' => $this->description,
            'details' => $this->details,
            'file_path' => $this->filePath,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            scannerName: $data['scanner_name'],
            severity: SeverityLevel::from($data['severity']),
            title: $data['title'],
            description: $data['description'],
            details: $data['details'] ?? [],
            filePath: $data['file_path'] ?? null,
        );
    }
}
