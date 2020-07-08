<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use SPFLib\Decoder;
use SPFLib\Semantic\Issue;
use SPFLib\SemanticValidator;

class SemanticValidatorTest extends TestCase
{
    /**
     * @var \SPFLib\Decoder
     */
    protected static $decoder;

    /**
     * @var \SPFLib\SemanticValidator
     */
    protected static $validator;

    /**
     * {@inheritdoc}
     *
     * @see \PHPUnit\Framework\TestCase::setUpBeforeClass()
     */
    public static function setUpBeforeClass(): void
    {
        self::$decoder = new Decoder();
        self::$validator = new SemanticValidator();
    }

    public function provideNoWarningsCases(): array
    {
        return [
            ['v=spf1 a mx include:d1.com include:d2.com include:d3.com include:d4.com include:d5.com include:d6.com include:d7.com redirect=foo.bar'],
            ['v=spf1 a mx all'],
            ['v=spf1 all'],
            ['v=spf1 redirect=foo.bar'],
            ['v=spf1 mx redirect=foo.bar'],
            ['v=spf1 mx exp=baz'],
            ['v=spf1 mx redirect=foo.bar exp=baz'],
        ];
    }

    /**
     * @dataProvider provideNoWarningsCases
     */
    public function testNoWarnings(string $txtRecord): void
    {
        $record = self::$decoder->getRecordFromTXT($txtRecord);
        $warnings = self::$validator->validate($record);
        $this->assertSame([], $warnings);
    }

    public function provideWarningsCases(): array
    {
        return [
            [
                'v=spf1 a mx include:d1.com include:d2.com include:d3.com include:d4.com include:d5.com include:d6.com include:d7.com include:d8.com redirect=foo.bar',
                [
                    Issue::CODE_TOO_MANY_DNS_LOOKUPS,
                ],
            ],
            [
                'v=spf1 a all mx',
                [
                    Issue::CODE_ALL_NOT_LAST_MECHANISM,
                ],
            ],
            [
                'v=spf1 all redirect=foo.bar',
                [
                    Issue::CODE_ALL_AND_REDIRECT,
                ],
            ],
            [
                'v=spf1 ptr:foo.bar',
                [
                    Issue::CODE_SHOULD_AVOID_PTR,
                ],
            ],
            [
                'v=spf1 exp=1 -all',
                [
                    Issue::CODE_MODIFIER_NOT_AFTER_MECHANISMS,
                ],
            ],
            [
                'v=spf1 redirect=foo.bar all',
                [
                    Issue::CODE_ALL_AND_REDIRECT,
                    Issue::CODE_MODIFIER_NOT_AFTER_MECHANISMS,
                ],
            ],
            [
                'v=spf1 mx redirect=foo.bar exp=baz redirect=qux',
                [
                    Issue::CODE_DUPLICATED_MODIFIER,
                ],
            ],
            [
                'v=spf1 mx redirect=foo.bar exp=baz redirect=qux exp=foo exp=bar',
                [
                    Issue::CODE_DUPLICATED_MODIFIER,
                    Issue::CODE_DUPLICATED_MODIFIER,
                ],
            ],
            [
                'v=spf1 mx include=foo',
                [
                    Issue::UNKNOWN_MODIFIER,
                ],
            ],
        ];
    }

    /**
     * @dataProvider provideWarningsCases
     */
    public function testWarnings(string $txtRecord, array $warningCodes): void
    {
        $record = self::$decoder->getRecordFromTXT($txtRecord);
        $warnings = self::$validator->validate($record);
        $this->assertSameSize($warningCodes, $warnings);
        foreach ($warnings as $warning) {
            $this->assertInstanceOf(Issue::class, $warning);
            $this->assertContains($warning->getCode(), $warningCodes);
        }
    }
}
