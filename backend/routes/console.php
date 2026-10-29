<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schedule;

/*
 * Abandoned-job recovery. Runs every minute so a crashed worker is noticed
 * within one heartbeat window rather than never.
 */
Schedule::command('scans:reap')
    ->everyMinute()
    ->withoutOverlapping()
    ->runInBackground();
