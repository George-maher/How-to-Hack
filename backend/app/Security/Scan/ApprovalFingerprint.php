<?php

declare(strict_types=1);

namespace App\Security\Scan;

/**
 * Computes the digest that binds an approval to exactly one scope + plan.
 *
 * Bumping the version invalidates every existing approval, which is the
 * intended behaviour when the approval semantics change.
 */
final class ApprovalFingerprint
{
    private const VERSION = 1;

    /**
     * @param  list<int>     $ports
     * @param  list<string>  $tools
     * @param  array<string, mixed>  $options
     */
    public static function for(string $host, array $ports, array $tools, array $options = []): string
    {
        $ports = array_values(array_unique(array_map('intval', $ports)));
        sort($ports, SORT_NUMERIC);

        $tools = array_values(array_unique(array_map('strval', $tools)));
        sort($tools, SORT_STRING);

        return CanonicalJson::hash([
            'v' => self::VERSION,
            'host' => strtolower(trim($host)),
            'ports' => $ports,
            'tools' => $tools,
            'options' => $options,
        ]);
    }
}
