<?php

namespace App\Services;

use App\Contracts\ProjectRepositoryInterface;
use App\Contracts\ScanRepositoryInterface;
use App\Models\Project;
use App\Models\Scan;

class ProjectService
{
    public function __construct(
        private readonly ProjectRepositoryInterface $projectRepository,
        private readonly ScanRepositoryInterface $scanRepository,
    ) {}

    public function create(array $data): Project
    {
        return $this->projectRepository->create($data);
    }

    public function update(int $id, array $data): Project
    {
        $project = $this->projectRepository->findById($id);
        if (!$project) {
            throw new \RuntimeException("Project not found: {$id}");
        }
        return $this->projectRepository->update($project, $data);
    }

    public function delete(int $id): void
    {
        $project = $this->projectRepository->findById($id);
        if (!$project) {
            throw new \RuntimeException("Project not found: {$id}");
        }
        $this->projectRepository->delete($project);
    }

    public function initiateScan(int $projectId): Scan
    {
        $project = $this->projectRepository->findById($projectId);
        if (!$project) {
            throw new \RuntimeException("Project not found: {$projectId}");
        }

        $activeScans = $project->activeScans()->count();
        if ($activeScans > 0) {
            throw new \RuntimeException('Project has active scans. Wait for completion.');
        }

        $scan = $this->scanRepository->create([
            'project_id' => $projectId,
            'status' => 'pending',
            'ai_reasoning' => [],
            'completed_scanners' => [],
        ]);

        dispatch(new \App\Jobs\RunScanJob($scan));

        return $scan;
    }
}
