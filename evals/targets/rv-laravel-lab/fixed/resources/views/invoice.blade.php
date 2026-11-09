@extends('layout')
@section('title', $invoice->number)
@section('content')
<h1 id="number">{{ $invoice->number }}</h1>
<p>Customer: {{ $invoice->customer }}</p>
<p>Amount: {{ number_format($invoice->amount_cents / 100, 2) }}</p>
<div class="notes">{{ $invoice->notes }}</div>
@endsection
