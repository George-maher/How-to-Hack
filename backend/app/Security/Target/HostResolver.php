<?php

declare(strict_types=1);

namespace App\Security\Target;

/**
 * Resolves a hostname to addresses.
 *
 * An interface, because tests must be able to simulate DNS answers — including
 * a record that changes between the authorisation check and execution.
 */
interface HostResolver
{
    /**
     * @return list<string> canonical IP literals (may be empty when the name
     *                      does not resolve)
     */
    public function resolve(string $host): array;
}
