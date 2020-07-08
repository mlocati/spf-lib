<?php

declare(strict_types=1);

use IPLib\Address\IPv4;
use IPLib\Address\IPv6;
use PHPUnit\Framework\TestCase;
use SPFLib\Decoder;
use SPFLib\Exception;
use SPFLib\Record;
use SPFLib\Term;
use SPFLib\Term\Mechanism;
use SPFLib\Term\Modifier;
use SPFLib\Test\FakeDnsResoler;

class DecoderTest extends TestCase
{
    public function provideNoResults(): array
    {
        return [
            [[]],
            [['foo', 'bar']],
            [['v=spf2']],
            [[' v=spf1']],
            [['v =spf1']],
            [['v = spf1']],
            [['v=spf 1']],
            [['V=spf1']],
            [['v=SPF1']],
            [['V=SPF1']],
        ];
    }

    /**
     * @dataProvider provideNoResults
     */
    public function testNoResults(array $txtRecords): void
    {
        $factory = new Decoder(new FakeDnsResoler($txtRecords));
        $record = $factory->getRecordFromDomain('example.org');
        $this->assertNull($record);
    }

    public function testMultipleRecords(): void
    {
        $domain = 'example.org';
        $records = ['v=spf1', 'v=spf1 mx'];
        $factory = new Decoder(new FakeDnsResoler(array_merge(['foo'], $records)));
        $error = null;
        try {
            $factory->getRecordFromDomain($domain);
        } catch (Throwable $x) {
            $error = $x;
        }
        $this->assertInstanceOf(Exception\MultipleSPFRecordsException::class, $error);
        $this->assertSame($domain, $error->getDomain());
        $this->assertSame($records, $error->getRecords());
    }

    public function provideValidTerms(): array
    {
        return [
            ['all', new Mechanism\AllMechanism(Mechanism::QUALIFIER_PASS)],
            ['+all', new Mechanism\AllMechanism(Mechanism::QUALIFIER_PASS), 'all'],
            ['-all', new Mechanism\AllMechanism(Mechanism::QUALIFIER_FAIL)],
            ['~all', new Mechanism\AllMechanism(Mechanism::QUALIFIER_SOFTFAIL)],
            ['?all', new Mechanism\AllMechanism(Mechanism::QUALIFIER_NEUTRAL)],
            ['include:foo.bar', new Mechanism\IncludeMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar')],
            ['a', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS)],
            ['a:foo.bar', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar')],
            ['a:foo.bar/4', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar', 4)],
            ['a:foo.bar//8', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar', null, 8)],
            ['a:foo.bar/4//8', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar', 4, 8)],
            ['a/4', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, '', 4)],
            ['a/0', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, '', 0)],
            ['a//0', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, '', null, 0)],
            ['a//0/0', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, '', 0, 0), 'a/0//0'],
            ['a//8', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, '', null, 8)],
            ['a/4//8', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, '', 4, 8)],
            ['a/32', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS), 'a'],
            ['a//128', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS), 'a'],
            ['a/32//64', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, '', null, 64), 'a//64'],
            ['a//64/32', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, '', null, 64), 'a//64'],
            ['a/4//128', new Mechanism\AMechanism(Mechanism::QUALIFIER_PASS, '', 4), 'a/4'],
            ['mx', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS)],
            ['mx:foo.bar', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar')],
            ['mx:foo.bar/4', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar', 4)],
            ['mx:foo.bar//8', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar', null, 8)],
            ['mx:foo.bar/4//8', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar', 4, 8)],
            ['mx/4', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS, '', 4)],
            ['mx//8', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS, '', null, 8)],
            ['mx/4//8', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS, '', 4, 8)],
            ['mx/32', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS), 'mx'],
            ['mx//128', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS), 'mx'],
            ['mx/32//64', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS, '', null, 64), 'mx//64'],
            ['mx/4//128', new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS, '', 4), 'mx/4'],
            ['ptr', new Mechanism\PtrMechanism(Mechanism::QUALIFIER_PASS)],
            ['ptr:foo.bar', new Mechanism\PtrMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar')],
            ['-ip4:1.2.3.4', new Mechanism\Ip4Mechanism(Mechanism::QUALIFIER_FAIL, IPv4::fromString('1.2.3.4'))],
            ['?ip4:1.2.3.4/5', new Mechanism\Ip4Mechanism(Mechanism::QUALIFIER_NEUTRAL, IPv4::fromString('1.2.3.4'), 5)],
            ['ip4:1.2.3.4/0', new Mechanism\Ip4Mechanism(Mechanism::QUALIFIER_PASS, IPv4::fromString('1.2.3.4'), 0)],
            ['+ip4:1.2.3.4/32', new Mechanism\Ip4Mechanism(Mechanism::QUALIFIER_PASS, IPv4::fromString('1.2.3.4')), 'ip4:1.2.3.4'],
            ['-ip6:::1', new Mechanism\Ip6Mechanism(Mechanism::QUALIFIER_FAIL, IPv6::fromString('::1'))],
            ['?ip6:1::0000:2/5', new Mechanism\Ip6Mechanism(Mechanism::QUALIFIER_NEUTRAL, IPv6::fromString('1::2'), 5), '?ip6:1::2/5'],
            ['ip6:1::2/0', new Mechanism\Ip6Mechanism(Mechanism::QUALIFIER_PASS, IPv6::fromString('1::2'), 0), 'ip6:1::2/0'],
            ['+ip6:1::2/128', new Mechanism\Ip6Mechanism(Mechanism::QUALIFIER_PASS, IPv6::fromString('1::2')), 'ip6:1::2'],
            ['exists:foo.bar', new Mechanism\ExistsMechanism(Mechanism::QUALIFIER_PASS, 'foo.bar')],
            ['redirect=foo.bar', new Modifier\RedirectModifier('foo.bar')],
            ['exp=foo.bar', new Modifier\ExpModifier('foo.bar')],
            ['unknown=modifier', new Modifier\UnknownModifier('unknown', 'modifier')],
        ];
    }

    /**
     * @dataProvider provideValidTerms
     */
    public function testValidTerm(string $rawTerm, Term $expected, ?string $expectedStringRepresentation = null): void
    {
        $factory = new Decoder(new FakeDnsResoler([Record::PREFIX . " {$rawTerm}"]));
        $actualRecord = $factory->getRecordFromDomain('example.org');
        $actualTerm = $actualRecord->getTerms()[0];
        $this->assertEquals($expected, $actualTerm);
        if ($expectedStringRepresentation === null) {
            $expectedStringRepresentation = $rawTerm;
        }
        $this->assertSame($expectedStringRepresentation, (string) $actualTerm);
    }

    public function provideInvalidTerms(): array
    {
        return [
            ['All'],
            ['all:'],
            ['?all:foo'],
            ['include'],
            ['include:'],
            ['include/foo.bar'],
            ['A'],
            ['a:'],
            ['a:/1'],
            ['a/33'],
            ['a/00'],
            ['a//00'],
            ['a/08'],
            ['a//010'],
            ['a/1/2'],
            ['a//129'],
            ['a//1//2'],
            ['a/1:foo.bar'],
            ['Mx'],
            ['mx/33'],
            ['mx/1/2'],
            ['mx//129'],
            ['mx//1//2'],
            ['mx/1:foo.bar'],
            ['ptr:'],
            ['ip4'],
            ['ip4:'],
            ['ip4:a'],
            ['ip4:0:1::2'],
            ['ip4:1.2.3.4/01'],
            ['ip4:1.2.3.4/33'],
            ['ip6'],
            ['ip6:'],
            ['ip6:a'],
            ['ip6:127.0.0.1'],
            ['ip6:::1/01'],
            ['ip6:::1/129'],
            ['exists'],
            ['exists:'],
            ['exists/foo.bar'],
            ['redirect'],
            ['redirect='],
            ['redirect:foo.bar'],
            ['exp'],
            ['exp='],
            ['exp:foo.bar'],
        ];
    }

    /**
     * @dataProvider provideInvalidTerms
     */
    public function testInvalidTerm(string $rawTerm): void
    {
        $factory = new Decoder();
        $error = null;
        try {
            $factory->getRecordFromTXT(Record::PREFIX . " {$rawTerm}");
        } catch (Throwable $x) {
            $error = $x;
        }
        $this->assertInstanceOf(Exception\InvalidTermException::class, $error);
        $this->assertSame($rawTerm, $error->getTerm());
    }
}
