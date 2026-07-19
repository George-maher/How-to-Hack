<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scan_results', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->string('scanner_name');
            $table->string('severity')->default('info');
            $table->string('title');
            $table->text('description');
            $table->json('details')->nullable();
            $table->string('file_path')->nullable();
            $table->timestamps();

            $table->index(['scan_id', 'scanner_name']);
            $table->index('severity');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scan_results');
    }
};
