<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\ProjectController;
use App\Http\Controllers\Api\ReportController;
use App\Http\Controllers\Api\ScanController;
use App\Http\Controllers\Api\ScanResultController;
use App\Http\Controllers\Api\ScannerController;

Route::middleware('api')->group(function () {

    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);

    Route::middleware('auth.api')->group(function () {

        Route::post('/logout', [AuthController::class, 'logout']);
        Route::get('/me', [AuthController::class, 'me']);

        Route::get('/scanners', [ScannerController::class, 'index']);

        Route::apiResource('projects', ProjectController::class);
        Route::post('/projects/{project}/scan', [ProjectController::class, 'scan']);

        Route::get('/projects/{project}/scans', [ScanController::class, 'index']);
        Route::get('/scans/{scan}', [ScanController::class, 'show']);
        Route::post('/scans/{scan}/cancel', [ScanController::class, 'cancel']);

        Route::get('/scans/{scan}/results', [ScanResultController::class, 'index']);
        Route::get('/scans/{scan}/results/severity', [ScanResultController::class, 'severityBreakdown']);

        Route::get('/reports/formats', [ReportController::class, 'formats']);
        Route::get('/reports', [ReportController::class, 'all']);
        Route::get('/scans/{scan}/reports', [ReportController::class, 'index']);
        Route::post('/scans/{scan}/reports', [ReportController::class, 'generate']);
        Route::get('/reports/{report}', [ReportController::class, 'show']);
        Route::post('/reports/{report}/regenerate', [ReportController::class, 'regenerate']);
        Route::get('/reports/{report}/download', [ReportController::class, 'download']);
        Route::delete('/reports/{report}', [ReportController::class, 'destroy']);
    });
});
