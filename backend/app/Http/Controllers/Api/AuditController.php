<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\AuditEvent;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Recent security events, newest first.
 *
 * Read-only and bounded: the audit trail is not an analytics endpoint.
 */
class AuditController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $limit = min(200, max(1, (int) $request->query('limit', 50)));

        $query = AuditEvent::query()->latest('id')->limit($limit);

        $event = $request->query('event');
        if (is_string($event) && $event !== '') {
            $query->where('event', 'like', $event.'%');
        }

        return response()->json([
            'events' => $query->get()->map(fn (AuditEvent $e) => [
                'id' => $e->id,
                'event' => $e->event,
                'decision' => $e->decision,
                'actor_type' => $e->actor_type,
                'actor_id' => $e->actor_id,
                'subject_type' => $e->subject_type,
                'subject_id' => $e->subject_id,
                'target' => $e->target,
                'context' => $e->context,
                'created_at' => $e->created_at?->toIso8601String(),
            ])->all(),
        ]);
    }
}
