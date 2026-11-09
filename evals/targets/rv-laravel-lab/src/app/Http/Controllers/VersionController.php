<?php

namespace App\Http\Controllers;

class VersionController extends Controller
{
    public function show()
    {
        $build = is_file(base_path('BUILD')) ? trim(file_get_contents(base_path('BUILD'))) : 'dev';

        return response()->json([
            'app' => config('app.name'),
            'build' => $build,
            'commit' => env('SOURCE_COMMIT', 'unknown'),
            'framework' => app()->version(),
        ])->header('X-Build-Id', $build);
    }
}
