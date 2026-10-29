<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Models\User;
use App\Services\Security\AuditLogger;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Bearer-token authentication.
 *
 * Tokens are stored hashed and compared in constant time; a failed attempt is
 * audited (without the token) so credential stuffing is visible.
 */
class AuthenticateApi
{
    public function __construct(private readonly AuditLogger $audit)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();

        if (! is_string($token) || $token === '') {
            return response()->json([
                'message' => 'Authentication required. Sign in again.',
                'code' => 'unauthenticated',
            ], 401);
        }

        $hash = hash('sha256', $token);

        $user = User::query()->where('api_token', $hash)->first();

        if (! $user instanceof User) {
            $this->audit->record(AuditLogger::AUTH_TOKEN_INVALID, 'denied', [
                'path' => $request->path(),
                'reason' => 'unknown_token',
            ], null, null, $request);

            return response()->json([
                'message' => 'Your session has expired. Sign in again.',
                'code' => 'unauthenticated',
            ], 401);
        }

        // Constant-time confirmation of the stored hash (defence in depth: the
        // lookup itself is a hash equality match on an indexed column).
        if (! hash_equals((string) $user->api_token, $hash)) {
            return response()->json([
                'message' => 'Your session has expired. Sign in again.',
                'code' => 'unauthenticated',
            ], 401);
        }

        $user->setAttribute('last_used_at', null);
        auth()->setUser($user);

        $request->setUserResolver(static fn () => $user);

        return $next($request);
    }
}
