<?php

declare(strict_types=1);

namespace App\Security\Target;

/**
 * Rebuilds a target URL around the host the policy actually approved.
 *
 * The Runner refuses a job whose `target.url` and `target.host` disagree, which
 * is what stops a caller from having a tool talk to a destination the policy
 * never saw. That means the API cannot simply forward the operator's original
 * string: `http://2130706433/` is `127.0.0.1` after normalization, and
 * `https://APP.example.com/` is `app.example.com`.
 *
 * The path and query are preserved — a scan is usually of a specific
 * application path, not of the bare origin.
 */
final class TargetUrl
{
    public static function rebuild(string $originalUrl, string $approvedHost, string $scheme, int $port): string
    {
        $scheme = strtolower($scheme);

        if (! in_array($scheme, ['http', 'https'], true)) {
            $scheme = 'https';
        }

        $port = $port >= 1 && $port <= 65535 ? $port : ($scheme === 'https' ? 443 : 80);

        // An IPv6 literal must be bracketed inside a URL authority.
        $literal = str_contains($approvedHost, ':') ? '['.$approvedHost.']' : $approvedHost;

        $path = parse_url($originalUrl, PHP_URL_PATH);
        $path = is_string($path) && $path !== '' ? $path : '/';

        // A path must start with "/" or it would become part of the authority.
        if (! str_starts_with($path, '/')) {
            $path = '/'.$path;
        }

        $query = parse_url($originalUrl, PHP_URL_QUERY);
        $suffix = is_string($query) && $query !== '' ? '?'.$query : '';

        $defaultPort = $scheme === 'https' ? 443 : 80;
        $authority = $port === $defaultPort ? $literal : $literal.':'.$port;

        return $scheme.'://'.$authority.$path.$suffix;
    }
}
