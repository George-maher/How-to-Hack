<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('audit_events', function (Blueprint $table) {
            $table->id();

            $table->string('actor_type', 16)->default('system');
            $table->unsignedBigInteger('actor_id')->nullable();

            // e.g. auth.login_failed, scope.denied, approval.granted, scan.failed
            $table->string('event', 64)->index();

            $table->string('subject_type', 64)->nullable();
            $table->string('subject_id', 64)->nullable();

            // allowed | denied | requested | recorded | unconfirmed
            $table->string('decision', 16)->default('recorded')->index();

            // The target involved, when relevant. Never a secret.
            $table->string('target', 255)->nullable();

            $table->json('context')->nullable();
            $table->string('ip', 45)->nullable();

            $table->timestamp('created_at')->useCurrent()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('audit_events');
    }
};
