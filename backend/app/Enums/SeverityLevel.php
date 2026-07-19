<?php

namespace App\Enums;

enum SeverityLevel: string
{
    case Info = 'info';
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public function weight(): int
    {
        return match ($this) {
            self::Info => 1,
            self::Low => 2,
            self::Medium => 3,
            self::High => 4,
            self::Critical => 5,
        };
    }

    public static function fromWeight(int $weight): self
    {
        return match (true) {
            $weight >= 5 => self::Critical,
            $weight >= 4 => self::High,
            $weight >= 3 => self::Medium,
            $weight >= 2 => self::Low,
            default => self::Info,
        };
    }
}
