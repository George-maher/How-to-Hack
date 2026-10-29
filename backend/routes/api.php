<?php

declare(strict_types=1);

use App\Http\Controllers\Api\ApprovalController;
use App\Http\Controllers\Api\AuditController;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\PolicyController;
use App\Http\Controllers\Api\ProjectController;
use App\Http\Controllers\Api\ReportController;
use App\Http\Controllers\Api\ScanController;
use App\Http\Controllers\Api\ScanResultController;
use App\Http\Controllers\Api\ScannerController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API routes
|--------------------------------------------------------------------------
|
| Registration is disabled by default (see config/security.php). Authentication
| is a bearer token; authorisation is per-object via policies inside each
| controller. Route-model binding means an unknown id is a 404, never a silent
| empty result.
|
*/

Route::middleware('api')->group(function () {

    Route::post('/login', [AuthController::class, 'login'])
        ->middleware('throttle:auth-login');

    if (config('security.allow_registration', false)) {
        Route::post('/register', [AuthController::class, 'register'])
            ->middleware('throttle:auth-register');
    }

    Route::middleware('auth.api')->group(function () {

        Route::post('/logout', [AuthController::class, 'logout']);
        Route::get('/me', [AuthController::class, 'me']);

        Route::get('/scanners', [ScannerController::class, 'index']);
        Route::get('/policy', [PolicyController::class, 'show']);

        Route::apiResource('projects', ProjectController::class);
        Route::post('/projects/{project}/scan', [ProjectController::class, 'scan']);

        Route::get('/projects/{project}/scans', [ScanController::class, 'index']);
        Route::get('/scans/{scan}', [ScanController::class, 'show'])->name('scans.show');
        Route::post('/scans/{scan}/cancel', [ScanController::class, 'cancel']);

        Route::get('/scans/{scan}/results', [ScanResultController::class, 'index']);
        Route::get('/scans/{scan}/results/severity', [ScanResultController::class, 'severityBreakdown']);

        // Explicit approval of active scans. The only way an approval becomes
        // valid; the planner and the worker have no access to these routes.
        Route::get('/approvals', [ApprovalController::class, 'index']);
        Route::get('/approvals/{approval}', [ApprovalController::class, 'show']);
        Route::post('/approvals/{approval}/approve', [ApprovalController::class, 'approve']);
        Route::post('/approvals/{approval}/reject', [ApprovalController::class, 'reject']);

        Route::get('/reports/formats', [ReportController::class, 'formats']);
        Route::get('/reports', [ReportController::class, 'all']);
        Route::get('/scans/{scan}/reports', [ReportController::class, 'index']);
        Route::post('/scans/{scan}/reports', [ReportController::class, 'generate']);
        Route::get('/reports/{report}', [ReportController::class, 'show'])->name('reports.show');
        Route::post('/reports/{report}/regenerate', [ReportController::class, 'regenerate']);
        Route::get('/reports/{report}/download', [ReportController::class, 'download'])->name('reports.download');
        Route::delete('/reports/{report}', [ReportController::class, 'destroy']);

        Route::get('/audit', [AuditController::class, 'index']);
    });
});
