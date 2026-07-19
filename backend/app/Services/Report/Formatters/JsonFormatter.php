<?php

namespace App\Services\Report\Formatters;

class JsonFormatter implements ReportFormatterInterface
{
    public function format(array $data): string
    {
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public function getMimeType(): string
    {
        return 'application/json';
    }

    public function getExtension(): string
    {
        return 'json';
    }
}
