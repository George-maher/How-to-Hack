<?php

return [
    'registry' => [
        \App\Scanners\PortScanner::class,
        \App\Scanners\DnsEnumerator::class,
        \App\Scanners\SslScanner::class,
        \App\Scanners\HttpAnalyzer::class,
        \App\Scanners\DirectoryBruteForcer::class,
        \App\Scanners\TechnologyDetector::class,
        \App\Scanners\WhoisLookup::class,
        \App\Scanners\SubdomainEnumerator::class,

        \App\Scanners\SecurityHeadersScanner::class,
        \App\Scanners\ApiAssessmentScanner::class,
        \App\Scanners\XssAssessmentScanner::class,
        \App\Scanners\SqlInjectionAssessmentScanner::class,

        \App\Scanners\Docker\NmapScanner::class,
        \App\Scanners\Docker\HttpxScanner::class,
        \App\Scanners\Docker\WhatWebScanner::class,
        \App\Scanners\Docker\DnsReconScanner::class,
        \App\Scanners\Docker\SubfinderScanner::class,
        \App\Scanners\Docker\AmassScanner::class,
        \App\Scanners\Docker\TheHarvesterScanner::class,

        \App\Scanners\Docker\DirsearchScanner::class,
        \App\Scanners\Docker\FfufScanner::class,
        \App\Scanners\Docker\KatanaScanner::class,
        \App\Scanners\Docker\HakrawlerScanner::class,
        \App\Scanners\Docker\GauScanner::class,
        \App\Scanners\Docker\WaybackUrlsScanner::class,

        \App\Scanners\Docker\NucleiScanner::class,
        \App\Scanners\Docker\NiktoScanner::class,
        \App\Scanners\Docker\WapitiScanner::class,
        \App\Scanners\Docker\SslScanScanner::class,
        \App\Scanners\Docker\TestSslScanner::class,
    ],

    'timeout' => env('SCANNER_TIMEOUT', 30),

    'retry' => [
        'max_attempts' => env('SCANNER_RETRY_ATTEMPTS', 3),
        'delay' => env('SCANNER_RETRY_DELAY', 1000),
    ],

    'parallel' => [
        'max_concurrent' => env('SCANNER_MAX_CONCURRENT', 5),
    ],

    'directories' => [
        'wordlist' => env('SCANNER_DIR_WORDLIST', storage_path('scanner/wordlists/common.txt')),
    ],

    'docker' => [
        'image' => env('SCANNER_DOCKER_IMAGE', 'howtohack/scanner:latest'),
        'network' => env('SCANNER_DOCKER_NETWORK', 'host'),
        'memory_limit' => env('SCANNER_DOCKER_MEMORY', '512m'),
        'timeout' => env('SCANNER_DOCKER_TIMEOUT', 120),
    ],
];
