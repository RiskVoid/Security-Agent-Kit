<?php

namespace App\Models;

use App\Models\Concerns\BelongsToTenant;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Invoice extends Model
{
    use BelongsToTenant;

    protected $fillable = ['organization_id', 'created_by', 'number', 'customer', 'amount_cents', 'notes', 'status'];

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }
}
