<?php

declare(strict_types=1);

namespace App\Security\Scan;

/**
 * Deterministic JSON encoding.
 *
 * Used for approval fingerprints so that logically identical configurations
 * always produce the same digest regardless of key or list order.
 */
final class CanonicalJson
{
    public static function encode(mixed $value): string
    {
        $normalised = self::normalise($value);

        $encoded = json_encode($normalised, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $encoded === false ? '{}' : $encoded;
    }

    public static function hash(mixed $value): string
    {
        return hash('sha256', self::encode($value));
    }

    private static function normalise(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        if (array_is_list($value)) {
            $items = array_map(static fn ($item) => self::normalise($item), $value);
            sort($items, SORT_STRING);

            return $items;
        }

        ksort($value, SORT_STRING);

        foreach ($value as $key => $item) {
            $value[$key] = self::normalise($item);
        }

        return $value;
    }
}
