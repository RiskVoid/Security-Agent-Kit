<?php

namespace App\Policies;

use App\Models\Export;
use App\Models\User;

class ExportPolicy
{
    public function download(User $user, Export $export): bool
    {
        return $user->organization_id === $export->organization_id && $user->isAdmin();
    }
}
