<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\PromoCode;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class PromoController extends Controller
{
    /**
     * FIXED: the check and the update are one transaction with a row lock, so a simultaneous burst
     * redeems at most max_uses times - the clean control of the race test (the vulnerable build's
     * controller has no lock: see src/app/Http/Controllers/Api/PromoController.php).
     */
    public function redeem(Request $request)
    {
        $data = $request->validate(['code' => ['required', 'string']]);

        return DB::transaction(function () use ($request, $data) {
            $promo = PromoCode::where('organization_id', $request->user()->organization_id)
                ->where('code', $data['code'])->lockForUpdate()->first();
            if (!$promo) {
                return response()->json(['error' => 'unknown promo code'], 404);
            }
            if ($promo->uses_count >= $promo->max_uses) {
                return response()->json(['error' => 'already fully redeemed', 'remaining' => 0], 409);
            }
            PromoCode::where('id', $promo->id)->increment('uses_count');
            $promo->refresh();
            return response()->json(['code' => $promo->code, 'remaining' => $promo->max_uses - $promo->uses_count]);
        }, 3);
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
