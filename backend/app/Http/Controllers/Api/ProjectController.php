<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Contracts\ProjectRepositoryInterface;
use App\Exceptions\TargetNotAuthorised;
use App\Http\Controllers\Controller;
use App\Http\Requests\InitiateScanRequest;
use App\Http\Requests\StoreProjectRequest;
use App\Http\Requests\UpdateProjectRequest;
use App\Http\Resources\ProjectResource;
use App\Models\Project;
use App\Services\ProjectService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class ProjectController extends Controller
{
    public function __construct(
        private readonly ProjectRepositoryInterface $projectRepository,
        private readonly ProjectService $projectService,
    ) {
    }

    public function index(Request $request): AnonymousResourceCollection
    {
        // Scoped to the caller. The previous implementation returned every
        // project in the database.
        return ProjectResource::collection(
            $this->projectRepository->allForUser($request->user())
        );
    }

    public function store(StoreProjectRequest $request): JsonResponse
    {
        $project = $this->projectService->create([
            ...$request->validated(),
            'user_id' => $request->user()->getKey(),
        ]);

        return response()->json(new ProjectResource($project), 201);
    }

    public function show(Project $project): JsonResponse
    {
        $this->authorize('view', $project);

        return response()->json(new ProjectResource($this->projectRepository->findWithScans($project)));
    }

    public function update(UpdateProjectRequest $request, Project $project): JsonResponse
    {
        $this->authorize('update', $project);

        $updated = $this->projectService->update($project, $request->validated());

        return response()->json(new ProjectResource($updated));
    }

    public function destroy(Project $project): JsonResponse
    {
        $this->authorize('delete', $project);

        $this->projectService->delete($project);

        return response()->json(['message' => 'Project deleted']);
    }

    /**
     * Start a scan. Active scanners require approval, which is requested here
     * and granted (or not) by a separate, audited call.
     */
    public function scan(InitiateScanRequest $request, Project $project): JsonResponse
    {
        $this->authorize('scan', $project);

        try {
            $scan = $this->projectService->initiateScan(
                $project,
                $request->validated(),
                $request->user(),
            );
        } catch (TargetNotAuthorised $e) {
            return response()->json($e->toArray(), 403);
        } catch (\RuntimeException $e) {
            return response()->json(['message' => $e->getMessage(), 'code' => 'scan_not_started'], 422);
        }

        $payload = [
            'message' => $scan->statusEnum()->isInFlight() && $scan->status->value === 'awaiting_approval'
                ? 'This scan needs approval before it can run.'
                : 'Scan queued.',
            'scan_id' => $scan->getKey(),
            'status' => $scan->statusEnum()->value,
            'requires_approval' => $scan->statusEnum()->value === 'awaiting_approval',
        ];

        if ($payload['requires_approval']) {
            $approval = $scan->approvals()->latest('id')->first();
            $payload['approval_id'] = $approval?->getKey();
            $payload['approval'] = $approval?->only([
                'id', 'status', 'target_host', 'target_ports', 'tools', 'expires_at',
            ]);
        }

        return response()->json($payload, 202);
    }
}
