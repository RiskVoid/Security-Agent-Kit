@extends('layout')
@section('title', 'Dashboard')
@section('content')
<h1>{{ $user->organization->name }} invoices</h1>
<table>
<tr><th>Number</th><th>Customer</th><th>Amount</th></tr>
@foreach ($invoices as $invoice)
<tr><td><a href="/invoices/{{ $invoice->id }}">{{ $invoice->number }}</a></td><td>{{ $invoice->customer }}</td>
<td>{{ number_format($invoice->amount_cents / 100, 2) }}</td></tr>
@endforeach
</table>
@endsection
