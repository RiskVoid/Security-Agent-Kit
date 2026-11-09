<?php

namespace App\Http\Controllers;

use App\Models\Export;
use Illuminate\Support\Facades\Storage;

class ExportController extends Controller
{
    // Route middleware can:download,export and the Export tenant scope protect this action.
    public function download(Export $export)
    {
        return Storage::disk('local')->download($export->path, $export->filename);
    }
}
