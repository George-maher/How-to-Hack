<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\Security\AuditLogger;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function __construct(private readonly AuditLogger $audit)
    {
    }

    public function register(Request $request): JsonResponse
    {
        if (! config('security.allow_registration', false)) {
            return response()->json([
                'message' => 'Registration is disabled on this instance.',
                'code' => 'registration_disabled',
            ], 403);
        }

        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:12', 'confirmed'],
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        $token = $this->generateToken($user);

        return response()->json([
            'user' => $this->userPayload($user),
            'token' => $token,
        ], 201);
    }

    public function login(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        $user = User::where('email', $validated['email'])->first();

        // Always run a hash comparison so a missing account and a wrong password
        // take the same time.
        $valid = $user !== null && Hash::check($validated['password'], (string) $user->password);

        if (! $valid) {
            $this->audit->record(AuditLogger::AUTH_LOGIN_FAILED, 'denied', [
                'email' => $validated['email'],
            ], null, null, $request);

            return response()->json([
                'message' => 'Those credentials do not match our records.',
                'code' => 'invalid_credentials',
            ], 401);
        }

        $token = $this->generateToken($user);

        $this->audit->record(AuditLogger::AUTH_LOGIN_SUCCEEDED, 'allowed', [
            'user_id' => $user->getKey(),
        ], null, $user, $request);

        return response()->json([
            'user' => $this->userPayload($user),
            'token' => $token,
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        $user = $request->user();

        $this->audit->record(AuditLogger::AUTH_LOGOUT, 'allowed', [], null, $user, $request);

        $user->forceFill(['api_token' => null])->save();

        return response()->json(['message' => 'Signed out.']);
    }

    public function me(Request $request): JsonResponse
    {
        return response()->json($this->userPayload($request->user()));
    }

    /**
     * @return array<string, mixed>
     */
    private function userPayload(User $user): array
    {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
        ];
    }

    private function generateToken(User $user): string
    {
        $token = Str::random(80);

        // Hashing means a database read alone does not yield a usable token.
        $user->forceFill(['api_token' => hash('sha256', $token)])->save();

        return $token;
    }
}
