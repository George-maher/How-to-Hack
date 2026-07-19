<?php

namespace Database\Seeders;

use App\Models\Project;
use App\Models\Scan;
use App\Models\ScanResult;
use App\Models\User;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        $user = User::factory()->create([
            'name' => 'Test User',
            'email' => 'test@example.com',
        ]);

        $project = Project::factory()->create([
            'user_id' => $user->id,
            'name' => 'Example Security Audit',
            'target_url' => 'https://example.com',
            'description' => 'Sample project for demonstration',
        ]);

        $scan = Scan::factory()->create([
            'project_id' => $project->id,
            'status' => 'completed',
            'completed_scanners' => ['port_scanner', 'dns_enumerator', 'http_analyzer', 'technology_detector'],
        ]);

        $scannerFindings = [
            'port_scanner' => [
                ['severity' => 'medium', 'title' => 'Open ports detected', 'description' => 'Found 3 open ports on example.com'],
                ['severity' => 'high', 'title' => 'Open port: 22/SSH', 'description' => 'Port 22 (SSH) is open'],
                ['severity' => 'medium', 'title' => 'Open port: 80/HTTP', 'description' => 'Port 80 (HTTP) is open'],
            ],
            'dns_enumerator' => [
                ['severity' => 'info', 'title' => 'DNS records found', 'description' => 'Found A, MX, NS records'],
                ['severity' => 'low', 'title' => 'Mail servers exposed', 'description' => 'Found 2 MX records'],
            ],
            'http_analyzer' => [
                ['severity' => 'high', 'title' => 'Missing security header: Content-Security-Policy', 'description' => 'CSP header is not set'],
                ['severity' => 'medium', 'title' => 'Missing security header: X-Frame-Options', 'description' => 'Clickjacking protection missing'],
            ],
            'technology_detector' => [
                ['severity' => 'info', 'title' => 'Technologies detected', 'description' => 'Detected: nginx, PHP, jQuery'],
            ],
        ];

        foreach ($scannerFindings as $scannerName => $findings) {
            foreach ($findings as $finding) {
                ScanResult::factory()->create([
                    'scan_id' => $scan->id,
                    'scanner_name' => $scannerName,
                    'severity' => $finding['severity'],
                    'title' => $finding['title'],
                    'description' => $finding['description'],
                ]);
            }
        }
    }
}
