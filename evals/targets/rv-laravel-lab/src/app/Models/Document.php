<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Document extends Model
{
    protected $fillable = ['organization_id', 'uploaded_by', 'filename', 'path'];
}
