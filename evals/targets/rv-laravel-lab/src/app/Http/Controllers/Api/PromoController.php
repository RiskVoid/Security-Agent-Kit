<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\PromoCode;
use Illuminate\Http\Request;

class PromoController extends Controller
{
    /**
     * REAL: race condition (API6:2023, CWE-362) - the seeded lab case of the kit's race_request tool.
     * The check (uses_count >= max_uses) and the update are two steps with no lock between them, so
     * simultaneous requests all read the same uses_count and all pass. One approval fires the whole
     * burst; the read-back (/api/promo/{code}) shows uses beyond max_uses.
     */
    public function redeem(Request $request)
    {
        $data = $request->validate(['code' => ['required', 'string']]);
        $promo = PromoCode::where('organization_id', $request->user()->organization_id)
            ->where('code', $data['code'])->first();
        if (!$promo) {
            return response()->json(['error' => 'unknown promo code'], 404);
        }
        if ($promo->uses_count >= $promo->max_uses) {
            return response()->json(['error' => 'already fully redeemed', 'remaining' => 0], 409);
        }
        PromoCode::where('id', $promo->id)->increment('uses_count');
        $promo->refresh();
        return response()->json(['code' => $promo->code, 'remaining' => $promo->max_uses - $promo->uses_count]);
    }

    public function status(Request $request, string $code)
    {
        $promo = PromoCode::where('organization_id', $request->user()->organization_id)
            ->where('code', $code)->first();
        if (!$promo) {
            return response()->json(['error' => 'unknown promo code'], 404);
        }
        return response()->json(['code' => $promo->code, 'max_uses' => $promo->max_uses,
            'uses' => $promo->uses_count]);
    }
}
