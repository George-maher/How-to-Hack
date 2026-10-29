<?php

declare(strict_types=1);

namespace App\Security\Scan;

use App\Enums\ScannerIntrusiveness;

/**
 * The exact set of scanners a scan is authorized to run, plus the options that
 * influence execution.
 *
 * The plan is the AI's sandbox: the planner may choose *which* approved scanner
 * runs next, but it can never add a tool, widen the target, or escalate to an
 * active scanner that the operator did not approve.
 */
final class ScanPlan
{
    /**
     * @param  array<string, ScannerIntrusiveness>  $intrusiveness  scanner name => classification
     * @param  array<string, mixed>                 $options
     */
    private function __construct(
        private readonly array $intrusiveness,
        private readonly array $options,
    ) {
    }

    /**
     * @param  array<int, string>                   $tools
     * @param  array<string, ScannerIntrusiveness>  $intrusiveness
     * @param  array<string, mixed>                 $options
     */
    public static function create(array $tools, array $intrusiveness, array $options = []): self
    {
        $filtered = [];
        foreach ($tools as $tool) {
            $name = (string) $tool;
            if ($name === '' || !isset($intrusiveness[$name])) {
                continue;
            }
            $filtered[$name] = $intrusiveness[$name];
        }

        ksort($filtered, SORT_STRING);

        return new self($filtered, self::normaliseOptions($options));
    }

    /**
     * Rebuild a plan from its persisted array form.
     *
     * Intrusiveness is re-derived from the registry rather than trusted from the
     * stored payload, so a tampered `plan.tools[].intrusiveness` cannot downgrade
     * an active scanner to passive and skip approval.
     */
    public static function fromArray(array $plan, \App\Scanners\Registry\ScannerRegistry $registry): self
    {
        $tools = is_array($plan['tools'] ?? null) ? array_values($plan['tools']) : [];
        $options = is_array($plan['options'] ?? null) ? $plan['options'] : [];

        $intrusiveness = [];
        foreach ($tools as $tool) {
            $name = (string) $tool;
            $intrusiveness[$name] = $registry->all()->has($name)
                ? $registry->get($name)->intrusiveness()
                : ScannerIntrusiveness::Active;
        }

        return self::create($tools, $intrusiveness, $options);
    }

    /**
     * @return list<string>
     */
    public function tools(): array
    {
        return array_keys($this->intrusiveness);
    }

    public function has(string $tool): bool
    {
        return isset($this->intrusiveness[$tool]);
    }

    /**
     * Intrusiveness of a tool inside this plan. Unknown tools are Active.
     */
    public function intrusivenessOf(string $tool): ScannerIntrusiveness
    {
        return $this->intrusiveness[$tool] ?? ScannerIntrusiveness::Active;
    }

    /**
     * @return list<string>
     */
    public function activeTools(): array
    {
        return array_keys(array_filter(
            $this->intrusiveness,
            static fn (ScannerIntrusiveness $i) => $i->requiresApproval(),
        ));
    }

    /**
     * @return list<string>
     */
    public function passiveTools(): array
    {
        return array_keys(array_filter(
            $this->intrusiveness,
            static fn (ScannerIntrusiveness $i) => !$i->requiresApproval(),
        ));
    }

    public function requiresApproval(): bool
    {
        return $this->activeTools() !== [];
    }

    public function isPassiveOnly(): bool
    {
        return !$this->requiresApproval();
    }

    /**
     * @return array<string, mixed>
     */
    public function options(): array
    {
        return $this->options;
    }

    public function option(string $key, mixed $default = null): mixed
    {
        return $this->options[$key] ?? $default;
    }

    /**
     * Digest binding an approval to a target, its ports, its tool set and its
     * execution options. Any change to any of these invalidates the approval.
     *
     * @param  list<int>  $ports
     */
    public function fingerprint(string $host, array $ports): string
    {
        return ApprovalFingerprint::for($host, $ports, $this->tools(), $this->options);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'tools' => $this->tools(),
            'active_tools' => $this->activeTools(),
            'passive_tools' => $this->passiveTools(),
            'requires_approval' => $this->requiresApproval(),
            'options' => $this->options,
        ];
    }

    /**
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    private static function normaliseOptions(array $options): array
    {
        $allowed = [
            'max_scanners' => static fn ($v) => is_numeric($v) ? max(1, min(60, (int) $v)) : null,
            'include_dependencies' => static fn ($v) => is_bool($v) ? $v : null,
            'notes' => static fn ($v) => is_string($v) ? mb_substr($v, 0, 500) : null,
        ];

        $normalised = [];
        foreach ($allowed as $key => $sanitiser) {
            if (!array_key_exists($key, $options)) {
                continue;
            }
            $value = $sanitiser($options[$key]);
            if ($value !== null) {
                $normalised[$key] = $value;
            }
        }

        ksort($normalised, SORT_STRING);

        return $normalised;
    }
}
