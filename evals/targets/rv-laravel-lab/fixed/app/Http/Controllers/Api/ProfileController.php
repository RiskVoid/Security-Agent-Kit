<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\UpdateSettingsRequest;
use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function me(Request $request)
    {
        return $request->user()->makeVisible([])->only(['id', 'name', 'email', 'role', 'organization_id',
            'is_platform_admin', 'timezone']);
    }

    public function update(Request $request)
    {
        $request->user()->update($request->validate(['name' => ['sometimes', 'string', 'max:100']]));

        return $this->me($request);
    }

    public function settings(UpdateSettingsRequest $request)
    {
        $request->user()->update($request->validated());

        return $this->me($request);
    }
}
