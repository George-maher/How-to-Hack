<?php

namespace App\Services\Report\Formatters;

interface ReportFormatterInterface
{
    public function format(array $data): string;
    public function getMimeType(): string;
    public function getExtension(): string;
}
