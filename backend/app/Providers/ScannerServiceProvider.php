<?php

namespace App\Providers;

use App\Contracts\AiProviderInterface;
use App\Contracts\ProjectRepositoryInterface;
use App\Contracts\ReportRepositoryInterface;
use App\Contracts\ScanRepositoryInterface;
use App\Contracts\ScanResultRepositoryInterface;
use App\Repositories\Eloquent\ProjectRepository;
use App\Repositories\Eloquent\ReportRepository;
use App\Repositories\Eloquent\ScanRepository;
use App\Repositories\Eloquent\ScanResultRepository;
use App\Scanners\Registry\ScannerRegistry;
use Illuminate\Support\ServiceProvider;

class ScannerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ScannerRegistry::class, function ($app) {
            $scannerClasses = config('scanners.registry', []);
            return new ScannerRegistry($scannerClasses);
        });

        $this->app->bind(ProjectRepositoryInterface::class, ProjectRepository::class);
        $this->app->bind(ScanRepositoryInterface::class, ScanRepository::class);
        $this->app->bind(ScanResultRepositoryInterface::class, ScanResultRepository::class);
        $this->app->bind(ReportRepositoryInterface::class, ReportRepository::class);
    }

    public function boot(): void
    {
        //
    }
}
