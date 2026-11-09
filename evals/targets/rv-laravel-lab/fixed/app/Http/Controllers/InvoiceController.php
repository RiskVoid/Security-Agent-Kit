<?php

namespace App\Http\Controllers;

use App\Models\Invoice;

class InvoiceController extends Controller
{
    public function show(Invoice $invoice)
    {
        $this->authorize('view', $invoice);

        return view('invoice', ['invoice' => $invoice]);
    }
}
