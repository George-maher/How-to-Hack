<?php

declare(strict_types=1);

namespace App\Providers;

use App\Services\Runner\RunnerClient;
use App\Services\Scan\ScannerExecutor;
use App\Services\Scan\ScanOrchestrator;
use App\Services\Security\ApprovalService;
use App\Services\Security\AuditLogger;
use App\Services\Security\LabExceptionStore;
use App\Services\Security\TargetScopeService;
use App\Security\Http\SafeHttpClient;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->register(ScannerServiceProvider::class);

        // Security services are singletons: the audit logger and the policy
        // configuration must be consistent within one request/worker cycle.
        $this->app->singleton(AuditLogger::class);
        $this->app->singleton(LabExceptionStore::class);
        $this->app->singleton(TargetScopeService::class);
        $this->app->singleton(ApprovalService::class);
        $this->app->singleton(SafeHttpClient::class);
        $this->app->singleton(ScannerExecutor::class);

        $this->app->singleton(RunnerClient::class, static fn () => RunnerClient::fromConfig());
        $this->app->singleton(ScanOrchestrator::class);
    }

    public function boot(): void
    {
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute(120)->by($request->user()?->id ?: $request->ip());
        });

        /*
         * Login is limited per account+IP and per IP. A shared IP must not let
         * one attacker lock every user out, and one IP must not be able to spray
         * an unlimited number of accounts.
         */
        RateLimiter::for('auth-login', function (Request $request) {
            $email = Str::lower((string) $request->input('email'));

            return [
                Limit::perMinute(5)->by('login:'.$email.'|'.$request->ip()),
                Limit::perMinute(20)->by('login-ip:'.$request->ip()),
            ];
        });

        RateLimiter::for('auth-register', function (Request $request) {
            return Limit::perHour(3)->by($request->ip());
        });
    }
}
