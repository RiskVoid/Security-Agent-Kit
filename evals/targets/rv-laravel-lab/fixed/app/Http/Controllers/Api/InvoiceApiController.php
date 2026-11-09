<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Invoice;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;

class InvoiceApiController extends Controller
{
    public function index(Request $request)
    {
        return Invoice::where('organization_id', $request->user()->organization_id)->orderBy('number')->get();
    }

    public function show(Invoice $invoice)
    {
        $this->authorize('view', $invoice);

        return $invoice;
    }

    public function update(Request $request, Invoice $invoice)
    {
        $this->authorize('update', $invoice);
        $invoice->update($request->validate([
            'customer' => ['sometimes', 'string', 'max:200'],
            'notes' => ['sometimes', 'nullable', 'string', 'max:2000'],
            'status' => ['sometimes', 'in:draft,sent,paid'],
        ]));

        return $invoice;
    }

    public function send(Request $request, Invoice $invoice)
    {
        $this->authorize('update', $invoice);
        // External effect: in the lab MAIL_MAILER=log, so nothing leaves the container.
        Mail::raw("Invoice {$invoice->number}", fn ($m) => $m->to('billing@'.$invoice->organization->slug.'.test'));
        $invoice->update(['status' => 'sent']);

        return response()->json(['sent' => $invoice->number]);
    }
}
