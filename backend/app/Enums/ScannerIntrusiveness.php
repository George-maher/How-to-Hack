<?php

declare(strict_types=1);

namespace App\Enums;

/**
 * How intrusive a scanner is.
 *
 * Passive scanners only read what the target already serves (banners, headers,
 * public DNS/WHOIS records). Active scanners send payloads, brute-force paths,
 * or otherwise interact in a way that requires explicit operator approval.
 *
 * Classification lives on the scanner itself (ScannerInterface::intrusiveness)
 * so that policy is defined by behaviour, not by tool name.
 */
enum ScannerIntrusiveness: string
{
    case Passive = 'passive';
    case Active = 'active';

    public function requiresApproval(): bool
    {
        return $this === self::Active;
    }

    public function label(): string
    {
        return $this === self::Active ? 'Active' : 'Passive';
    }
}
