<?php

namespace App\Enums;

enum ScannerCategory: string
{
    case Reconnaissance = 'reconnaissance';
    case Network = 'network';
    case WebApplication = 'web_application';
    case Infrastructure = 'infrastructure';
    case InformationDisclosure = 'information_disclosure';
    case VulnerabilityAssessment = 'vulnerability_assessment';
    case ApiAssessment = 'api_assessment';
    case SpecializedAssessment = 'specialized_assessment';

    public function label(): string
    {
        return match ($this) {
            self::Reconnaissance => 'Reconnaissance',
            self::Network => 'Network',
            self::WebApplication => 'Web Application',
            self::Infrastructure => 'Infrastructure',
            self::InformationDisclosure => 'Information Disclosure',
            self::VulnerabilityAssessment => 'Vulnerability Assessment',
            self::ApiAssessment => 'API Assessment',
            self::SpecializedAssessment => 'Specialized Assessment',
        };
    }

    public function priority(): int
    {
        return match ($this) {
            self::Network => 1,
            self::Reconnaissance => 2,
            self::InformationDisclosure => 3,
            self::WebApplication => 4,
            self::Infrastructure => 5,
            self::ApiAssessment => 6,
            self::VulnerabilityAssessment => 7,
            self::SpecializedAssessment => 8,
        };
    }
}
