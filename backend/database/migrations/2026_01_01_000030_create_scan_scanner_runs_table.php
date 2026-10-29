<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scan_scanner_runs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();

            $table->string('scanner', 64);
            $table->string('intrusiveness', 16);

            // Completed | invalid_output | failed | timed_out | unavailable |
            // blocked | cancelled | skipped
            $table->string('outcome', 24)->index();
            $table->unsignedTinyInteger('attempts')->default(1);

            $table->integer('exit_code')->nullable();
            $table->unsignedInteger('duration_ms')->nullable();
            $table->unsignedInteger('findings_count')->default(0);

            $table->string('error', 500)->nullable();
            $table->text('stderr_excerpt')->nullable();
            $table->json('diagnostics')->nullable();
            $table->string('runner_job_id', 64)->nullable();

            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->timestamps();

            $table->index(['scan_id', 'scanner']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scan_scanner_runs');
    }
};
