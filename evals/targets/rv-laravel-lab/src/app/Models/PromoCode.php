<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class PromoCode extends Model
{
    protected $fillable = ['organization_id', 'code', 'max_uses', 'uses_count'];
}
