<?php

declare(strict_types=1);

use SPFLib\Check\Environment;
use SPFLib\Check\State;
use SPFLib\Exception;
use SPFLib\Macro\MacroString;
use SPFLib\Macro\MacroString\Chunk\LiteralString;
use SPFLib\Macro\MacroString\Chunk\Placeholder;
use SPFLib\Macro\MacroString\Decoder;
use SPFLib\Macro\MacroString\Expander;
use SPFLib\Test\FakeDnsResoler;
use SPFLib\Test\TestCase;

class PlaceholderExpansionTest extends TestCase
{
    /**
     * @var \SPFLib\Macro\MacroString\Decoder
     */
    protected static $decoder;

    /**
     * @var \SPFLib\Macro\MacroString\Expander
     */
    protected static $expander;

    /**
     * {@inheritdoc}
     *
     * @see \PHPUnit\Framework\TestCase::setUpBeforeClass()
     */
    public static function setUpBeforeClass(): void
    {
        self::$decoder = Decoder::getInstance();
        self::$expander = new Expander();
    }

    public function provideValidPlaceholderCases(): array
    {
        $environment = new Environment('10.20.30.40', 'helo.sender.example.com', 'john-doe@sender.email.address.com', 'name.domain.mta');
        $state = new State\MailFromState(
            $environment,
            FakeDnsResoler::create()
                ->setFakePTRRecords(['40.30.20.10.in-addr.arpa' => ['resolved.sender.email.address.com']])
                ->setFakeForwardLookups(['resolved.sender.email.address.com' => ['10.20.30.40']])
        );
        $stateIPv6 = clone $state;
        $stateIPv6 = new State\MailFromState(
            new Environment('1234:abcd::ab12', $environment->getHeloDomain(), $environment->getMailFrom(), $environment->getCheckerDomain()),
            FakeDnsResoler::create()->setFakePTRRecords(['40.30.20.10.in-addr.arpa' => ['sender.example.com']])
        );
        $recordDomain = 'spf.example.org';

        return [
            // 0
            [
                '%{s}',
                [new Placeholder(Placeholder::ML_SENDER)],
                $state,
                $recordDomain,
                'john-doe@sender.email.address.com',
            ],
            // 1
            [
                '%{l}',
                [new Placeholder(Placeholder::ML_SENDER_LOCAL_PART)],
                $state,
                $recordDomain,
                'john-doe',
            ],
            // 2
            [
                '%{l-}',
                [new Placeholder(Placeholder::ML_SENDER_LOCAL_PART, null, false, '-')],
                $state,
                $recordDomain,
                'john.doe',
            ],
            // 3
            [
                '%{lr}',
                [new Placeholder(Placeholder::ML_SENDER_LOCAL_PART, null, true)],
                $state,
                $recordDomain,
                'john-doe',
            ],
            // 4
            [
                '%{lr-}',
                [new Placeholder(Placeholder::ML_SENDER_LOCAL_PART, null, true, '-')],
                $state,
                $recordDomain,
                'doe.john',
            ],
            // 5
            [
                '%{l1r-}',
                [new Placeholder(Placeholder::ML_SENDER_LOCAL_PART, 1, true, '-')],
                $state,
                $recordDomain,
                'john',
            ],
            // 6
            [
                '%{o}',
                [new Placeholder(Placeholder::ML_SENDER_DOMAIN)],
                $state,
                $recordDomain,
                'sender.email.address.com',
            ],
            // 7
            [
                '%{d}',
                [new Placeholder(Placeholder::ML_DOMAIN)],
                $state,
                $recordDomain,
                $recordDomain,
            ],
            // 8
            [
                '%{d4}',
                [new Placeholder(Placeholder::ML_DOMAIN, 4)],
                $state,
                $recordDomain,
                $recordDomain,
            ],
            // 9
            [
                '%{d3}',
                [new Placeholder(Placeholder::ML_DOMAIN, 3)],
                $state,
                $recordDomain,
                $recordDomain,
            ],
            // 10
            [
                '%{d2}',
                [new Placeholder(Placeholder::ML_DOMAIN, 2)],
                $state,
                $recordDomain,
                'example.org',
            ],
            // 11
            [
                '%{d1}',
                [new Placeholder(Placeholder::ML_DOMAIN, 1)],
                $state,
                $recordDomain,
                'org',
            ],
            // 12
            [
                '%{dr}',
                [new Placeholder(Placeholder::ML_DOMAIN, null, true)],
                $state,
                $recordDomain,
                'org.example.spf',
            ],
            // 13
            [
                '%{d2r}',
                [new Placeholder(Placeholder::ML_DOMAIN, 2, true)],
                $state,
                $recordDomain,
                'example.spf',
            ],
            // 14
            [
                '%{i}',
                [new Placeholder(Placeholder::ML_IP)],
                $state,
                $recordDomain,
                '10.20.30.40',
            ],
            // 15
            [
                '%{i}',
                [new Placeholder(Placeholder::ML_IP)],
                $stateIPv6,
                $recordDomain,
                '1.2.3.4.a.b.c.d.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.1.2',
            ],
            // 16
            [
                '%{p}',
                [new Placeholder(Placeholder::ML_IP_VALIDATED_DOMAIN)],
                $state,
                $recordDomain,
                'resolved.sender.email.address.com',
            ],
            // 17
            [
                '%{p2}',
                [new Placeholder(Placeholder::ML_IP_VALIDATED_DOMAIN, 2)],
                $state,
                $recordDomain,
                'address.com',
            ],
            // 18
            [
                '%{pr}',
                [new Placeholder(Placeholder::ML_IP_VALIDATED_DOMAIN, null, true)],
                $state,
                $recordDomain,
                'com.address.email.sender.resolved',
            ],
            // 19
            [
                '%{v}',
                [new Placeholder(Placeholder::ML_IP_TYPE)],
                $state,
                $recordDomain,
                'in-addr',
            ],
            // 20
            [
                '%{v}',
                [new Placeholder(Placeholder::ML_IP_TYPE)],
                $stateIPv6,
                $recordDomain,
                'ip6',
            ],
            // 21
            [
                '%{h}',
                [new Placeholder(Placeholder::ML_HELO_DOMAIN)],
                clone $state,
                $recordDomain,
                'helo.sender.example.com',
            ],
            // 22
            [
                '%{c}',
                [new Placeholder(Placeholder::ML_SMTP_CLIENT_IP)],
                $state,
                $recordDomain,
                '10.20.30.40',
            ],
            // 23
            [
                '%{c}',
                [new Placeholder(Placeholder::ML_SMTP_CLIENT_IP)],
                $stateIPv6,
                $recordDomain,
                '1234:abcd::ab12',
            ],
            // 24
            [
                '%{r}',
                [new Placeholder(Placeholder::ML_CHECKER_DOMAIN)],
                $stateIPv6,
                $recordDomain,
                'name.domain.mta',
            ],
            // 25
            [
                '%{r}',
                [new Placeholder(Placeholder::ML_CHECKER_DOMAIN)],
                new State\MailFromState(new Environment('', ''), FakeDnsResoler::create()),
                $recordDomain,
                Environment::UNKNOWN_CHECKER_DOMAIN,
            ],
            // 26
            [
                '%{t}',
                [new Placeholder(Placeholder::ML_CURRENT_TIMESTAMP)],
                new State\MailFromState(new Environment('', ''), FakeDnsResoler::create()),
                $recordDomain,
                '/^\d{' . strlen((string) time()) . '}$/',
                true,
            ],
            // 27
            [
                '%{ir}.%{v}._spf.%{d2}%%',
                [
                    new Placeholder(Placeholder::ML_IP, null, true),
                    new LiteralString('.'),
                    new Placeholder(Placeholder::ML_IP_TYPE),
                    new LiteralString('._spf.'),
                    new Placeholder(Placeholder::ML_DOMAIN, 2),
                    new LiteralString('%%'),
                ],
                $state,
                $recordDomain,
                '40.30.20.10.in-addr._spf.example.org%',
            ],
            // 28
            [
                '%%%-%_%%_%%%_%%%%_%%-1aZz!~',
                [new LiteralString('%%%-%_%%_%%%_%%%%_%%-1aZz!~')],
                $state,
                $recordDomain,
                '%%20 %_% %%_%-1aZz!~',
            ],
            // 29
            [
                chr(0x21),
                [new LiteralString('!')],
                $state,
                $recordDomain,
                '!',
            ],
            // 30
            [
                chr(0x7E),
                [new LiteralString('~')],
                $state,
                $recordDomain,
                '~',
            ],
            // 31
            [
                '%{ir}',
                [new Placeholder(Placeholder::ML_IP, null, true)],
                $stateIPv6,
                $recordDomain,
                '2.1.b.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.b.a.4.3.2.1',
            ],
        ];
    }

    /**
     * @dataProvider provideValidPlaceholderCases
     */
    public function testValidPlaceholderCase(string $dnsMacroString, array $expectedPlaceholders, State $state, string $domain, string $expectedResult, bool $isRegex = false, $decoderFlags = Decoder::FLAG_EXP): void
    {
        $state->resetDNSQueryCounters();
        $macroString = self::$decoder->decode($dnsMacroString, $decoderFlags);
        $expectedMacroString = new MacroString($expectedPlaceholders);
        $this->assertEquals($expectedMacroString, $macroString);
        $actualResult = self::$expander->expand($macroString, $domain, $state);
        if ($isRegex) {
            $this->assertRegularExpression($expectedResult, $actualResult);
        } else {
            $this->assertSame($expectedResult, $actualResult);
        }
        $this->assertSame($dnsMacroString, (string) $macroString);
    }

    public function provideMissingEnvironmentValueCases(): array
    {
        return [
            [Placeholder::ML_SENDER],
            [Placeholder::ML_SENDER_LOCAL_PART, Placeholder::ML_SENDER],
            [Placeholder::ML_SENDER_LOCAL_PART, null, new State\MailFromState(new Environment('', 'invalid', 'invalid'), FakeDnsResoler::create())],
            [Placeholder::ML_SENDER_DOMAIN, Placeholder::ML_SENDER],
            [Placeholder::ML_SENDER_DOMAIN, null, new State\MailFromState(new Environment('', 'invalid', 'invalid'), FakeDnsResoler::create())],
            [Placeholder::ML_IP],
            [Placeholder::ML_IP_VALIDATED_DOMAIN, Placeholder::ML_IP],
            [Placeholder::ML_IP_TYPE, Placeholder::ML_IP],
            [Placeholder::ML_HELO_DOMAIN],
            [Placeholder::ML_SMTP_CLIENT_IP, Placeholder::ML_IP],
            [Placeholder::ML_CHECKER_DOMAIN, null, new State\MailFromState(new Environment('', '', '', ''), FakeDnsResoler::create())],
        ];
    }

    /**
     * @dataProvider provideMissingEnvironmentValueCases
     */
    public function testMissingEnvironmentValueCase(string $macroLetter, ?string $expectedMissingMacroLetter = null, ?State $state = null, string $currentDomain = 'mail.example.org'): void
    {
        if ($state === null) {
            $state = new State\MailFromState(new Environment('', ''), FakeDnsResoler::create());
        }
        $macroString = new MacroString([new Placeholder($macroLetter)]);
        $error = null;
        try {
            self::$expander->expand($macroString, $currentDomain, $state);
        } catch (Exception\MissingEnvironmentValueException $x) {
            $error = $x;
        }
        $this->assertNotNull($error);
        if ($expectedMissingMacroLetter === null) {
            $expectedMissingMacroLetter = $macroLetter;
        }
        $this->assertSame($expectedMissingMacroLetter, $error->getEnvironmentValueIdentifier());
    }

    public function provideWrongMacroStrings(): array
    {
        return [
            [''],
            [chr(0x00)],
            [chr(0x10)],
            [chr(0x1F)],
            ["\n"],
            ["\r"],
            ["\t"],
            [' '],
            [chr(0x7F)],
            [chr(0x80)],
            [chr(0x81)],
            [chr(0xFF)],
            ['%'],
            ['%%%'],
            ['%%%'],
            ['%%%%%'],
            ['100%'],
            ['%100'],
            ['%{c}'],
            ['%{r}'],
            ['%{t}'],
            ['%{i0}'],
            ['%{irX}'],
            ['%{i1rX}'],
        ];
    }

    /**
     * @dataProvider provideWrongMacroStrings
     */
    public function testWrongMacroString(string $macroString, int $decoderFlags = Decoder::FLAG_NONE): void
    {
        $this->expectException(Exception\InvalidMacroStringException::class);
        self::$decoder->decode($macroString, $decoderFlags);
    }

    public function testEmpty(): void
    {
        $chunk = self::$decoder->decode('', Decoder::FLAG_ALLOWEMPTY);
        $this->assertTrue($chunk->isEmpty());
        $this->expectException(Exception\InvalidMacroStringException::class);
        self::$decoder->decode('');
    }

    public function testDecoder(): void
    {
        $spfDecoder = new SPFLib\Decoder();
        $this->expectException(Exception\InvalidMacroStringException::class);
        $spfDecoder->getRecordFromTXT('v=spf1 a:%(r))');
    }
}
