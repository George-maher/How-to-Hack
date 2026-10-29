<?php

declare(strict_types=1);

use App\Exceptions\ApprovalRequired;
use App\Exceptions\TargetNotAuthorised;
use App\Http\Middleware\AuthenticateApi;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->throttleApi();

        $middleware->alias([
            'auth.api' => AuthenticateApi::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        /*
         * Every failure mode below is an expected, correctly-handled outcome.
         * None of them may surface as a 500 or as a generic "something went
         * wrong", because the frontend renders specific guidance from `code`.
         */
        $exceptions->render(function (TargetNotAuthorised $e, Request $request) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json($e->toArray(), $e->httpStatus());
            }
        });

        $exceptions->render(function (ApprovalRequired $e, Request $request) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json($e->toArray(), 409);
            }
        });

        $exceptions->render(function (AuthorizationException $e, Request $request) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json([
                    'message' => 'You are not allowed to do that.',
                    'code' => 'forbidden',
                ], 403);
            }
        });

        $exceptions->render(function (AuthenticationException $e, Request $request) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json([
                    'message' => 'Your session has expired. Sign in again.',
                    'code' => 'unauthenticated',
                ], 401);
            }
        });

        $exceptions->render(function (NotFoundHttpException $e, Request $request) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json([
                    'message' => 'That resource does not exist.',
                    'code' => 'not_found',
                ], 404);
            }
        });
    })->create();
