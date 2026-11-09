<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SearchController extends Controller
{
    public function index(Request $request)
    {
        $org = $request->user()->organization_id;
        $q = $request->query('q', '');
        $rows = DB::select('select id, number, customer from invoices where organization_id = ? and customer like ?',
            [$org, '%'.$q.'%']);

        return response()->json(['query' => $q, 'results' => $rows]);
    }
}
