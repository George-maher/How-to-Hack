<?php

namespace Tests\Unit\Scanners;

use App\Scanners\Registry\ScannerRegistry;
use App\Scanners\PortScanner;
use App\Scanners\DnsEnumerator;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ScannerRegistryTest extends TestCase
{
    #[Test]
    public function it_registers_and_retrieves_scanners(): void
    {
        $registry = new ScannerRegistry([
            PortScanner::class,
            DnsEnumerator::class,
        ]);

        $this->assertEquals(2, $registry->count());
        $this->assertNotNull($registry->get('port_scanner'));
        $this->assertNotNull($registry->get('dns_enumerator'));
    }

    #[Test]
    public function it_filters_unused_scanners(): void
    {
        $registry = new ScannerRegistry([
            PortScanner::class,
            DnsEnumerator::class,
        ]);

        $unused = $registry->getUnused(['port_scanner']);
        $this->assertCount(1, $unused);
        $this->assertEquals('dns_enumerator', $unused->first()->name());
    }

    #[Test]
    public function it_throws_for_unknown_scanner(): void
    {
        $registry = new ScannerRegistry([]);
        $this->expectException(\App\Exceptions\ScannerNotFoundException::class);
        $registry->get('nonexistent');
    }
}
