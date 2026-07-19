<?php

namespace Tests\Unit\Enums;

use App\Enums\SeverityLevel;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class SeverityLevelTest extends TestCase
{
    #[Test]
    public function it_has_correct_weights(): void
    {
        $this->assertEquals(1, SeverityLevel::Info->weight());
        $this->assertEquals(2, SeverityLevel::Low->weight());
        $this->assertEquals(3, SeverityLevel::Medium->weight());
        $this->assertEquals(4, SeverityLevel::High->weight());
        $this->assertEquals(5, SeverityLevel::Critical->weight());
    }

    #[Test]
    public function it_creates_from_weight(): void
    {
        $this->assertEquals(SeverityLevel::Info, SeverityLevel::fromWeight(1));
        $this->assertEquals(SeverityLevel::High, SeverityLevel::fromWeight(4));
        $this->assertEquals(SeverityLevel::Critical, SeverityLevel::fromWeight(5));
    }
}
