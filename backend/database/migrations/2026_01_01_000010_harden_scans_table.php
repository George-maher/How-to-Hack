<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            // The plan the operator approved, and the digest that binds the
            // approval to it.
            $table->json('plan')->nullable();
            $table->string('plan_fingerprint', 64)->nullable()->index();

            // Resolved target state, recorded at creation and re-checked by the
            // worker and the Runner.
            $table->string('target_host', 253)->nullable();
            $table->json('target_ports')->nullable();
            $table->json('resolved_ips')->nullable();

            // Lifecycle bookkeeping.
            $table->timestamp('heartbeat_at')->nullable()->index();
            $table->timestamp('cancel_requested_at')->nullable();
            // Why the scan ended the way it did (see ScanOutcomeReason).
            $table->string('outcome_reason', 64)->nullable();
            $table->text('failure_detail')->nullable();
            $table->boolean('degraded')->default(false);

            $table->index('status');
        });

        // Target URLs are validated up to 2048 characters; varchar(255) would
        // silently truncate or error on legitimate long URLs.
        Schema::table('projects', function (Blueprint $table) {
            $table->string('target_url', 2048)->change();
        });

        // Legacy rows: `pending` was the old name for "created, not started".
        DB::table('scans')->where('status', 'pending')->update(['status' => 'queued']);
    }

    public function down(): void
    {
        Schema::table('projects', function (Blueprint $table) {
            $table->string('target_url', 255)->change();
        });

        DB::table('scans')->where('status', 'queued')->update(['status' => 'pending']);

        Schema::table('scans', function (Blueprint $table) {
            $table->dropIndex(['plan_fingerprint']);
            $table->dropIndex(['heartbeat_at']);
            $table->dropIndex(['status']);
            $table->dropColumn([
                'plan',
                'plan_fingerprint',
                'target_host',
                'target_ports',
                'resolved_ips',
                'heartbeat_at',
                'cancel_requested_at',
                'outcome_reason',
                'failure_detail',
                'degraded',
            ]);
        });
    }
};
