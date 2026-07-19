<?php

namespace App\Http\Controllers\Api;

use App\Contracts\ProjectRepositoryInterface;
use App\Http\Controllers\Controller;
use App\Http\Resources\ProjectResource;
use App\Services\ProjectService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class ProjectController extends Controller
{
    public function __construct(
        private readonly ProjectRepositoryInterface $projectRepository,
        private readonly ProjectService $projectService,
    ) {}

    public function index(): AnonymousResourceCollection
    {
        return ProjectResource::collection($this->projectRepository->all());
    }

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'target_url' => 'required|string|max:2048',
            'description' => 'nullable|string',
        ]);

        $validated['user_id'] = $request->user()->id;

        $project = $this->projectService->create($validated);
        return response()->json(new ProjectResource($project), 201);
    }

    public function show(int $id): JsonResponse
    {
        $project = $this->projectRepository->findWithScans($id);
        if (!$project) {
            return response()->json(['message' => 'Project not found'], 404);
        }
        return response()->json(new ProjectResource($project));
    }

    public function update(Request $request, int $id): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'sometimes|string|max:255',
            'target_url' => 'sometimes|string|max:2048',
            'description' => 'nullable|string',
            'status' => 'sometimes|string|in:active,inactive',
        ]);

        try {
            $project = $this->projectService->update($id, $validated);
            return response()->json(new ProjectResource($project));
        } catch (\RuntimeException $e) {
            return response()->json(['message' => $e->getMessage()], 404);
        }
    }

    public function destroy(int $id): JsonResponse
    {
        try {
            $this->projectService->delete($id);
            return response()->json(['message' => 'Project deleted'], 200);
        } catch (\RuntimeException $e) {
            return response()->json(['message' => $e->getMessage()], 404);
        }
    }

    public function scan(int $id): JsonResponse
    {
        try {
            $scan = $this->projectService->initiateScan($id);
            return response()->json([
                'message' => 'Scan initiated',
                'scan_id' => $scan->id,
            ], 202);
        } catch (\RuntimeException $e) {
            return response()->json(['message' => $e->getMessage()], 400);
        }
    }
}
