<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ledgerly @yield('title')</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:.4rem;text-align:left}.err{color:#b00}</style>
</head>
<body>
@auth
<nav><a href="/dashboard">Dashboard</a> | {{ auth()->user()->email }} ({{ auth()->user()->organization->name }})
<form method="post" action="/logout" style="display:inline">@csrf<button>Log out</button></form></nav>
@endauth
@yield('content')
</body>
</html>
