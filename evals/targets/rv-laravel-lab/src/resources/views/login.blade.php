@extends('layout')
@section('title', 'Log in')
@section('content')
<h1>Log in to Ledgerly</h1>
@error('email')<p class="err">{{ $message }}</p>@enderror
<form method="post" action="/login">
  @csrf
  <p><label>Email <input type="email" name="email" value="{{ old('email') }}" required></label></p>
  <p><label>Password <input type="password" name="password" required></label></p>
  <p><button type="submit">Log in</button></p>
</form>
@endsection
