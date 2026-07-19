<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('reports', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->string('title');
            $table->text('executive_summary')->nullable();
            $table->text('technical_summary')->nullable();
            $table->text('recommendations')->nullable();
            $table->json('scan_data')->nullable();
            $table->json('ai_analysis')->nullable();
            $table->string('format')->default('html');
            $table->string('status')->default('draft');
            $table->timestamps();

            $table->index('scan_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('reports');
    }
};
