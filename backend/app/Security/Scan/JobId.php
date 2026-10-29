<?php

declare(strict_types=1);

namespace App\Security\Scan;

/**
 * Deterministic Runner job identifiers.
 *
 * The id is the idempotency key for a scanner run: the Runner replays a
 * recorded result instead of starting a second container when it sees the same
 * id again. That makes two properties non-negotiable:
 *
 *  - **stable**: the same scan + tool + plan always yields the same id, so a
 *    duplicate queue delivery cannot cause a second execution;
 *  - **scoped**: the plan fingerprint is part of the digest, so a scan whose
 *    plan changed gets a different id rather than a stale replay.
 *
 * Framework-free so it can be verified without Laravel (see
 * tests/Standalone/runner_contract_test.php) and matched by the Runner's
 * validation regex in runner/src/validate.mjs.
 */
final class JobId
{
    /** The Runner rejects anything outside this shape. */
    public const PATTERN = '/^[A-Za-z0-9_-]{8,64}$/';

    public const MAX_LENGTH = 64;

    public static function for(int|string $scanId, string $tool, ?string $planFingerprint = null): string
    {
        // Keep only characters the Runner accepts, then bound the length.
        $scanner = substr(preg_replace('/[^a-z0-9]/', '', strtolower($tool)) ?: 'tool', 0, 24);

        $digest = substr(hash('sha256', implode('|', [
            (string) $scanId,
            $scanner,
            (string) ($planFingerprint ?? ''),
        ])), 0, 10);

        $id = sprintf('s%d-%s-%s', (int) $scanId, $scanner, $digest);

        // A pathological scan id could still push the string over the limit.
        if (strlen($id) > self::MAX_LENGTH) {
            $id = substr($id, -self::MAX_LENGTH);
        }

        return $id;
    }

    public static function isValid(string $id): bool
    {
        return preg_match(self::PATTERN, $id) === 1;
    }
}
