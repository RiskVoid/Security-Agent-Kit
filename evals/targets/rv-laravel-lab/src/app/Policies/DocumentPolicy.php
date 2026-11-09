<?php

namespace App\Policies;

use App\Models\Document;
use App\Models\User;

class DocumentPolicy
{
    public function download(User $user, Document $document): bool
    {
        return $user->organization_id === $document->organization_id;
    }
}
