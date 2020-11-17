<?php

declare(strict_types=1);

use IPLib\Address\IPv4;
use IPLib\Address\IPv6;
use SPFLib\Decoder;
use SPFLib\Record;
use SPFLib\Term\Mechanism;
use SPFLib\Term\Modifier;
use SPFLib\Test\TestCase;

class RecordTest extends TestCase
{
    public function testRecord(): void
    {
        $factory = new Decoder();
        $this->assertNull($factory->getRecordFromTXT('v:spf1 -all'));
        $record = $factory->getRecordFromTXT(Record::PREFIX . ' ~all foo=bar  -ip4:127.0.0.1 +ip6:::1 redirect=example.com');
        $this->assertInstanceOf(Record::class, $record);
        $all = new Mechanism\AllMechanism(Mechanism::QUALIFIER_SOFTFAIL);
        $unknownModifier = new Modifier\UnknownModifier('foo', 'bar');
        $ip4 = new Mechanism\Ip4Mechanism(Mechanism::QUALIFIER_FAIL, IPv4::fromString('127.0.0.1'));
        $ip6 = new Mechanism\Ip6Mechanism(Mechanism::QUALIFIER_PASS, IPv6::fromString('::1'));
        $redirect = new Modifier\RedirectModifier('example.com');
        $this->assertEquals(
            [
                $all,
                $unknownModifier,
                $ip4,
                $ip6,
                $redirect,
            ],
            $record->getTerms()
        );
        $this->assertEquals(
            [
                $all,
                $ip4,
                $ip6,
            ],
            $record->getMechanisms()
        );
        $this->assertEquals(
            [
                $unknownModifier,
                $redirect,
            ],
            $record->getModifiers()
        );
        $this->assertSame('v=spf1 ~all foo=bar -ip4:127.0.0.1 ip6:::1 redirect=example.com', (string) $record);
    }
}
