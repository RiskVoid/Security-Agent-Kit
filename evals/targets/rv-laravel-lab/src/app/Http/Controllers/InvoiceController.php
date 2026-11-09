<?php

namespace App\Http\Controllers;

use App\Models\Invoice;

class InvoiceController extends Controller
{
    public function show(Invoice $invoice)
    {
        return view('invoice', ['invoice' => $invoice]);
    }
}
