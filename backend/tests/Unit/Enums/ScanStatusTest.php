<?php

namespace Tests\Unit\Enums;

use App\Enums\ScanStatus;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ScanStatusTest extends TestCase
{
    #[Test]
    public function it_identifies_terminal_states(): void
    {
        $this->assertTrue(ScanStatus::Completed->isTerminal());
        $this->assertTrue(ScanStatus::Failed->isTerminal());
        $this->assertTrue(ScanStatus::Cancelled->isTerminal());
        $this->assertFalse(ScanStatus::Pending->isTerminal());
        $this->assertFalse(ScanStatus::Running->isTerminal());
    }

    #[Test]
    public function it_validates_transitions(): void
    {
        $this->assertTrue(ScanStatus::Pending->canTransitionTo(ScanStatus::Running));
        $this->assertTrue(ScanStatus::Pending->canTransitionTo(ScanStatus::Cancelled));
        $this->assertFalse(ScanStatus::Pending->canTransitionTo(ScanStatus::Completed));

        $this->assertTrue(ScanStatus::Running->canTransitionTo(ScanStatus::Completed));
        $this->assertTrue(ScanStatus::Running->canTransitionTo(ScanStatus::Failed));
        $this->assertFalse(ScanStatus::Completed->canTransitionTo(ScanStatus::Running));
    }
}
