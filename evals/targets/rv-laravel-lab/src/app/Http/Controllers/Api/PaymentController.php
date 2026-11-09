<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Payment;

class PaymentController extends Controller
{
    public function show(Payment $payment)
    {
        $this->authorize('view', $payment);

        return $payment;
    }
}
