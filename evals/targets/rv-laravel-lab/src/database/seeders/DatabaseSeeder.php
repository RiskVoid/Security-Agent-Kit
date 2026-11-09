<?php

namespace Database\Seeders;

use App\Models\Document;
use App\Models\Export;
use App\Models\Invoice;
use App\Models\Organization;
use App\Models\Payment;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Storage;

/**
 * Known lab fixtures (RiskVoid lab only: these accounts and records exist nowhere else).
 *
 *   acme   (organization 1): alice@acme.test (admin), bob@acme.test (member)
 *   globex (organization 2): carol@globex.test (admin)
 *
 * Every record carries a marker string (ACME-..., GLOBEX-...) so a test can tell whose data a response holds.
 */
class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        $acme = Organization::create(['name' => 'Acme Corp', 'slug' => 'acme']);
        $globex = Organization::create(['name' => 'Globex Inc', 'slug' => 'globex']);

        $alice = User::create(['organization_id' => $acme->id, 'name' => 'Alice Admin', 'email' => 'alice@acme.test',
            'role' => 'admin', 'password' => 'alice-lab-pass', 'api_token' => 'rvlab-alice-7f3a9c41d2']);
        $bob = User::create(['organization_id' => $acme->id, 'name' => 'Bob Member', 'email' => 'bob@acme.test',
            'role' => 'member', 'password' => 'bob-lab-pass', 'api_token' => 'rvlab-bob-2b8e41a6f0']);
        $carol = User::create(['organization_id' => $globex->id, 'name' => 'Carol Admin', 'email' => 'carol@globex.test',
            'role' => 'admin', 'password' => 'carol-lab-pass', 'api_token' => 'rvlab-carol-c04d17e9b3']);

        $i1 = Invoice::create(['organization_id' => $acme->id, 'created_by' => $alice->id, 'number' => 'ACME-INV-1001',
            'customer' => 'Wile E. Coyote', 'amount_cents' => 125000, 'notes' => 'ACME-CONFIDENTIAL-1001 rocket skates']);
        Invoice::create(['organization_id' => $acme->id, 'created_by' => $bob->id, 'number' => 'ACME-INV-1002',
            'customer' => 'Road Runner Ltd', 'amount_cents' => 4200, 'notes' => 'ACME-CONFIDENTIAL-1002']);
        $i3 = Invoice::create(['organization_id' => $globex->id, 'created_by' => $carol->id, 'number' => 'GLOBEX-INV-2001',
            'customer' => 'Hank Scorpio', 'amount_cents' => 990000, 'notes' => 'GLOBEX-CONFIDENTIAL-2001 doomsday device']);

        Payment::create(['organization_id' => $acme->id, 'invoice_id' => $i1->id, 'amount_cents' => 125000,
            'reference' => 'ACME-PAY-5001']);
        Payment::create(['organization_id' => $globex->id, 'invoice_id' => $i3->id, 'amount_cents' => 990000,
            'reference' => 'GLOBEX-PAY-6001']);

        Storage::disk('local')->put('documents/acme-contract.txt', "ACME-DOC-SECRET contract terms\n");
        Storage::disk('local')->put('documents/globex-contract.txt', "GLOBEX-DOC-SECRET contract terms\n");
        Document::create(['organization_id' => $acme->id, 'uploaded_by' => $alice->id, 'filename' => 'acme-contract.txt',
            'path' => 'documents/acme-contract.txt']);
        Document::create(['organization_id' => $globex->id, 'uploaded_by' => $carol->id,
            'filename' => 'globex-contract.txt', 'path' => 'documents/globex-contract.txt']);

        Storage::disk('local')->put('exports/acme-q3.csv', "number,amount\nACME-EXPORT-DATA,1250.00\n");
        Storage::disk('local')->put('exports/globex-q3.csv', "number,amount\nGLOBEX-EXPORT-DATA,9900.00\n");
        Export::create(['organization_id' => $acme->id, 'filename' => 'acme-q3.csv', 'path' => 'exports/acme-q3.csv']);
        Export::create(['organization_id' => $globex->id, 'filename' => 'globex-q3.csv', 'path' => 'exports/globex-q3.csv']);
    }
}
