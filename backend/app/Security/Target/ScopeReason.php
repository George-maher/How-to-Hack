<?php

declare(strict_types=1);

namespace App\Security\Target;

/**
 * Why a target was refused (or accepted).
 *
 * Every refusal has a distinct code so the API, the audit log and the UI can
 * explain *why* a scan did not run. A generic "not allowed" is not enough: an
 * operator needs to know whether the host is public but unlisted, private, or
 * an unresolved name.
 */
enum ScopeReason: string
{
    case Allowed = 'allowed';
    case AllowedByException = 'allowed_by_lab_exception';

    // Target parsing / resolution
    case InvalidUrl = 'invalid_url';
    case UnsupportedScheme = 'unsupported_scheme';
    case InvalidHost = 'invalid_host';
    case Unresolved = 'unresolved';
    case TooManyAddresses = 'too_many_addresses';

    // Address class
    case Loopback = 'loopback';
    case PrivateAddress = 'private_address';
    case LinkLocal = 'link_local';
    case CloudMetadata = 'cloud_metadata';
    case CarrierGradeNat = 'carrier_grade_nat';
    case Multicast = 'multicast';
    case Reserved = 'reserved';
    case Unspecified = 'unspecified';

    // Policy
    case NotAllowlisted = 'not_allowlisted';
    case PortNotAllowed = 'port_not_allowed';
    case AddressNotAllowed = 'address_not_allowed';
    case LabExceptionExpired = 'lab_exception_expired';
    case AddressChanged = 'address_changed';

    // Fail-closed catch-all
    case PolicyError = 'policy_error';

    public function isSuccess(): bool
    {
        return $this === self::Allowed || $this === self::AllowedByException;
    }

    /**
     * Operator-facing sentence. Deliberately specific: an unlisted public host
     * and a blocked private address are different problems with different fixes.
     */
    public function message(): string
    {
        return match ($this) {
            self::Allowed => 'The target is in the configured allowlist.',
            self::AllowedByException => 'The target is permitted by a scoped lab exception.',
            self::InvalidUrl => 'The target is not a valid absolute URL.',
            self::UnsupportedScheme => 'Only http and https targets are supported.',
            self::InvalidHost => 'The target host is not a valid hostname or IP address.',
            self::Unresolved => 'The target host could not be resolved.',
            self::TooManyAddresses => 'The target host resolves to too many addresses.',
            self::Loopback => 'Loopback addresses are blocked unless a lab exception covers them.',
            self::PrivateAddress => 'Private addresses are blocked unless a lab exception covers them.',
            self::LinkLocal => 'Link-local addresses are blocked.',
            self::CloudMetadata => 'Cloud metadata endpoints are always blocked.',
            self::CarrierGradeNat => 'Carrier-grade NAT addresses are blocked.',
            self::Multicast => 'Multicast addresses are not scannable.',
            self::Reserved => 'Reserved and non-routable addresses are blocked.',
            self::Unspecified => 'The unspecified address is blocked.',
            self::NotAllowlisted => 'The target is not in the configured allowlist.',
            self::PortNotAllowed => 'The requested port is not allowed for this target.',
            self::AddressNotAllowed => 'The target resolves to an address outside the allowlist.',
            self::LabExceptionExpired => 'The lab exception for this target has expired.',
            self::AddressChanged => 'The target now resolves to different addresses than were approved.',
            self::PolicyError => 'The target policy could not be evaluated, so the request was refused.',
        };
    }
}
