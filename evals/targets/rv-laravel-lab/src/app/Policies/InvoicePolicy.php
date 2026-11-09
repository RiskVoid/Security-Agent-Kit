<?php

namespace App\Policies;

use App\Models\Invoice;
use App\Models\User;

class InvoicePolicy
{
    public function view(User $user, Invoice $invoice): bool
    {
        return $user->organization_id === $invoice->organization_id;
    }

    public function update(User $user, Invoice $invoice): bool
    {
        return $user->organization_id === $invoice->organization_id && $user->isAdmin();
    }
}
