<?php

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Http\Request;

class DashboardController extends Controller
{
    public function index(Request $request)
    {
        $invoices = Invoice::where('organization_id', $request->user()->organization_id)->orderBy('number')->get();

        return view('dashboard', ['invoices' => $invoices, 'user' => $request->user()]);
    }
}
