<?php

namespace App\Models;

use App\Models\Concerns\BelongsToTenant;
use Illuminate\Database\Eloquent\Model;

class Export extends Model
{
    use BelongsToTenant;

    protected $fillable = ['organization_id', 'filename', 'path'];
}
