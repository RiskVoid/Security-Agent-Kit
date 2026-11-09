<?php

namespace App\Models\Concerns;

use App\Models\Scopes\TenantScope;

/**
 * Limits every query of the model to the signed-in user's organization (a global scope), so route model
 * binding of another organization's record finds nothing (404).
 */
trait BelongsToTenant
{
    public static function bootBelongsToTenant(): void
    {
        static::addGlobalScope(new TenantScope);
    }
}
