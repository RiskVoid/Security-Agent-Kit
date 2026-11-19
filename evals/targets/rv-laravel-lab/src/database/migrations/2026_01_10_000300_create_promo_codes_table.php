<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('promo_codes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained();
            $table->string('code');
            $table->unsignedInteger('max_uses')->default(1);
            $table->unsignedInteger('uses_count')->default(0);
            $table->timestamps();
            $table->unique(['organization_id', 'code']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('promo_codes');
    }
};
