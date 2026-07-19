<?php

namespace Tests\Unit\Services;

use App\Services\Ai\ReasoningChain;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ReasoningChainTest extends TestCase
{
    #[Test]
    public function it_adds_entries(): void
    {
        $chain = new ReasoningChain();
        $chain->add('port_scanner', 'Initial reconnaissance');

        $this->assertCount(1, $chain->all());
        $this->assertEquals('port_scanner', $chain->last()['scanner']);
    }

    #[Test]
    public function it_detects_duplicates(): void
    {
        $chain = new ReasoningChain();
        $chain->add('port_scanner', 'First');
        $chain->add('dns_enum', 'Second');
        $chain->add('port_scanner', 'Duplicate');

        $this->assertTrue($chain->hasDuplicates());
    }

    #[Test]
    public function it_lists_decisions(): void
    {
        $chain = new ReasoningChain();
        $chain->add('a', 'reason a');
        $chain->add('b', 'reason b');

        $this->assertEquals(['a', 'b'], $chain->decisions());
    }
}
