<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateApi
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        $user = \App\Models\User::where('api_token', hash('sha256', $token))->first();

        if (!$user) {
            return response()->json(['message' => 'Invalid or expired token'], 401);
        }

        auth()->setUser($user);

        return $next($request);
    }
}
