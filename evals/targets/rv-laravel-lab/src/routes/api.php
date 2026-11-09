<?php

use App\Http\Controllers\Api\InvoiceApiController;
use App\Http\Controllers\Api\PaymentController;
use App\Http\Controllers\Api\ProfileController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:api')->group(function () {
    Route::get('/me', [ProfileController::class, 'me']);
    Route::patch('/profile', [ProfileController::class, 'update']);
    Route::patch('/settings', [ProfileController::class, 'settings']);

    Route::get('/invoices', [InvoiceApiController::class, 'index']);
    Route::get('/invoices/{invoice}', [InvoiceApiController::class, 'show']);
    Route::put('/invoices/{invoice}', [InvoiceApiController::class, 'update']);
    Route::post('/invoices/{invoice}/send', [InvoiceApiController::class, 'send']);

    Route::get('/payments/{payment}', [PaymentController::class, 'show']);
});
