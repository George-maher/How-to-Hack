<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scan_approvals', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->foreignId('project_id')->constrained()->cascadeOnDelete();
            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();

            $table->string('status', 16)->default('pending')->index();

            // Exactly what was approved: target, ports, tool set, options.
            $table->string('target_url', 2048);
            $table->string('target_host', 253);
            $table->json('target_ports');
            $table->json('tools');
            $table->json('options')->nullable();
            $table->json('resolved_ips')->nullable();
            $table->string('fingerprint', 64)->index();
            $table->string('scope_rule', 64)->nullable();

            $table->timestamp('expires_at')->nullable();
            $table->timestamp('decided_at')->nullable();
            $table->foreignId('decided_by')->nullable()->constrained('users')->nullOnDelete();
            $table->string('decision_note', 500)->nullable();

            $table->timestamps();

            $table->index(['scan_id', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scan_approvals');
    }
};
