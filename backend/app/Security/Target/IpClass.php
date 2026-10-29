<?php

declare(strict_types=1);

namespace App\Security\Target;

/**
 * Address classification.
 *
 * Anything that is not `Public` is refused by default. The classes exist so the
 * refusal can be explained, and so a narrowly scoped lab exception can permit
 * `Loopback` or `Private` without ever permitting `CloudMetadata`.
 */
enum IpClass: string
{
    case Public = 'public';
    case Loopback = 'loopback';
    case Private = 'private';
    case LinkLocal = 'link_local';
    case CloudMetadata = 'cloud_metadata';
    case CarrierGradeNat = 'carrier_grade_nat';
    case Multicast = 'multicast';
    case Reserved = 'reserved';
    case Unspecified = 'unspecified';

    public function isPublic(): bool
    {
        return $this === self::Public;
    }

    /**
     * The refusal reason this class produces.
     */
    public function reason(): ScopeReason
    {
        return match ($this) {
            self::Public => ScopeReason::Allowed,
            self::Loopback => ScopeReason::Loopback,
            self::Private => ScopeReason::PrivateAddress,
            self::LinkLocal => ScopeReason::LinkLocal,
            self::CloudMetadata => ScopeReason::CloudMetadata,
            self::CarrierGradeNat => ScopeReason::CarrierGradeNat,
            self::Multicast => ScopeReason::Multicast,
            self::Reserved => ScopeReason::Reserved,
            self::Unspecified => ScopeReason::Unspecified,
        };
    }

    /**
     * Classes an operator may never whitelist, even with a lab exception.
     */
    public function isNeverPermittable(): bool
    {
        return in_array($this, [self::CloudMetadata, self::Multicast, self::Unspecified], true);
    }
}
