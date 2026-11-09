<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('invoices', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained();
            $table->foreignId('created_by')->constrained('users');
            $table->string('number');
            $table->string('customer');
            $table->unsignedInteger('amount_cents');
            $table->text('notes')->nullable();
            $table->string('status')->default('draft');
            $table->timestamps();
        });

        Schema::create('payments', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained();
            $table->foreignId('invoice_id')->constrained();
            $table->unsignedInteger('amount_cents');
            $table->string('reference');
            $table->timestamps();
        });

        Schema::create('documents', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained();
            $table->foreignId('uploaded_by')->constrained('users');
            $table->string('filename');
            $table->string('path');
            $table->timestamps();
        });

        Schema::create('exports', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained();
            $table->string('filename');
            $table->string('path');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('exports');
        Schema::dropIfExists('documents');
        Schema::dropIfExists('payments');
        Schema::dropIfExists('invoices');
    }
};
