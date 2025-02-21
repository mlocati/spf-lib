<?php

declare(strict_types=1);

use SPFLib\Decoder;
use SPFLib\OnlineSemanticValidator;
use SPFLib\Record;
use SPFLib\Semantic\Issue;
use SPFLib\Semantic\OnlineIssue;
use SPFLib\Test\FakeDnsResoler;
use SPFLib\Test\TestCase;

class OnlineSemanticValidatorTest extends TestCase
{
    /**
     * @var \SPFLib\Test\FakeDnsResoler
     */
    protected static $resolver;

    /**
     * @var \SPFLib\OnlineSemanticValidator
     */
    protected static $validator;

    /**
     * {@inheritdoc}
     *
     * @see \PHPUnit\Framework\TestCase::setUpBeforeClass()
     */
    public static function setUpBeforeClass(): void
    {
        self::$resolver = FakeDnsResoler::create();
        self::$validator = new OnlineSemanticValidator(new Decoder(self::$resolver));
    }

    /**
     * {@inheritdoc}
     *
     * @see \PHPUnit\Framework\TestCase::setUp()
     */
    public function setUp(): void
    {
        self::$resolver
            ->setFakeTXTRecords([])
            ->setFakeForwardLookups([])
            ->setFakeMXRecords([])
            ->setFakePTRRecords([])
            ->setFakeReverseLookups([])
        ;
    }

    public function feedValidateDomainCases(): array
    {
        return [
            [
                '',
                [OnlineIssue::CODE_NODOMAIN_NORECORD_PROVIDED],
            ],
            [
                '',
                [OnlineIssue::CODE_NODOMAIN_NORECORD_PROVIDED],
                [],
                OnlineIssue::LEVEL_FATAL,
            ],
            [
                'test.example.org',
                [OnlineIssue::CODE_RECORD_NOT_FOUND],
            ],
            [
                'test.example.org',
                [OnlineIssue::CODE_RECORD_NOT_FOUND],
                [],
                OnlineIssue::LEVEL_FATAL,
            ],
            [
                'test.example.org',
                [OnlineIssue::CODE_RECORD_FETCH_OR_PARSE_FAILED],
                ['test.example.org' => ['v=spf1 mal formed!']],
            ],
            [
                'test.example.org',
                [OnlineIssue::CODE_RECORD_FETCH_OR_PARSE_FAILED],
                ['test.example.org' => ['v=spf1 mal formed!']],
                OnlineIssue::LEVEL_FATAL,
            ],
            [
                'test.example.org',
                [OnlineIssue::CODE_RECURSIVE_DOMAIN_DETECTED],
                ['test.example.org' => ['v=spf1 redirect=test.example.org']],
            ],
            [
                'test.example.org',
                [OnlineIssue::CODE_RECURSIVE_DOMAIN_DETECTED],
                ['test.example.org' => ['v=spf1 redirect=test.example.org']],
            ],
            [
                'test1.example.org',
                [OnlineIssue::CODE_RECURSIVE_DOMAIN_DETECTED],
                [
                    'test1.example.org' => ['v=spf1 include:test2.example.org -all'],
                    'test2.example.org' => ['v=spf1 include:test3.example.org -all'],
                    'test3.example.org' => ['v=spf1 include:test1.example.org -all'],
                ],
            ],
            [
                'test1.example.org',
                [OnlineIssue::CODE_RECURSIVE_DOMAIN_DETECTED],
                [
                    'test1.example.org' => ['v=spf1 include:test2.example.org -all'],
                    'test2.example.org' => ['v=spf1 include:test3.example.org -all'],
                    'test3.example.org' => ['v=spf1 redirect=test2.example.org'],
                ],
            ],
            [
                'test1.example.org',
                [],
                [
                    'test1.example.org' => ['v=spf1 include:test2.example.org include:test3.example.org -all'],
                    'test2.example.org' => ['v=spf1 include:test4.example.org -all'],
                    'test3.example.org' => ['v=spf1 include:test4.example.org -all'],
                    'test4.example.org' => ['v=spf1 -all'],
                ],
            ],
            [
                'test.example.org',
                [OnlineIssue::CODE_DOMAIN_WITH_PLACEHOLDER],
                ['test.example.org' => ['v=spf1 include:_spf.%{d2} -all']],
            ],
            [
                'test.example.org',
                [],
                ['test.example.org' => ['v=spf1 include:_spf.%{d2} -all']],
                OnlineIssue::LEVEL_WARNING,
            ],
            [
                'test1.example.org',
                [OnlineIssue::CODE_TOO_MANY_DNS_LOOKUPS_ONLINE],
                [
                    'test1.example.org' => ['v=spf1 mx a include:test2.example.org include:test6.example.org include:test7.example.org ip4:1.2.3.4 ~all'],
                    'test2.example.org' => ['v=spf1 ip4:1.2.3.4 include:test3.example.org ~all'],
                    'test3.example.org' => ['v=spf1 ip4:1.2.3.4 include:test4.example.org ~all'],
                    'test4.example.org' => ['v=spf1 ip4:1.2.3.4 include:test5.example.org ~all'],
                    'test5.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test6.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test7.example.org' => ['v=spf1 include:test8.example.org include:test9.example.org include:test10.example.org ~all'],
                    'test8.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test9.example.org' => ['v=spf1 ~all'],
                    'test10.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                ],
            ],
            [
                'test1.example.org',
                [],
                [
                    'test1.example.org' => ['v=spf1 a include:test2.example.org include:test6.example.org include:test7.example.org ip4:1.2.3.4 ~all'],
                    'test2.example.org' => ['v=spf1 ip4:1.2.3.4 include:test3.example.org ~all'],
                    'test3.example.org' => ['v=spf1 ip4:1.2.3.4 include:test4.example.org ~all'],
                    'test4.example.org' => ['v=spf1 ip4:1.2.3.4 include:test5.example.org ~all'],
                    'test5.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test6.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test7.example.org' => ['v=spf1 include:test8.example.org include:test9.example.org include:test10.example.org ~all'],
                    'test8.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test9.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test10.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                ],
            ],
        ];
    }

    /**
     * @dataProvider feedValidateDomainCases
     */
    public function testValidateDomain(string $domain, array $expectedIssueCodes, array $txtRecords = [], ?int $minimumLevel = null): void
    {
        self::$resolver->setFakeTXTRecords($txtRecords);
        $issues = self::$validator->validateDomain($domain, $minimumLevel);
        $this->checkIssues($issues, $expectedIssueCodes, $minimumLevel);
    }

    public function feedValidateRawRecordCases(): array
    {
        return [
            [
                '', '',
                [OnlineIssue::CODE_RECORD_PARSE_FAILED],
            ],
            [
                '', '',
                [OnlineIssue::CODE_RECORD_PARSE_FAILED],
                OnlineIssue::LEVEL_FATAL,
            ],
            [
                'malformed', '',
                [OnlineIssue::CODE_RECORD_PARSE_FAILED],
            ],
            [
                'malformed', '',
                [OnlineIssue::CODE_RECORD_PARSE_FAILED],
                OnlineIssue::LEVEL_FATAL,
            ],
            [
                'v=spf1 malformed', '',
                [OnlineIssue::CODE_RECORD_PARSE_FAILED],
            ],
            [
                'v=spf1 malformed', '',
                [OnlineIssue::CODE_RECORD_PARSE_FAILED],
                OnlineIssue::LEVEL_FATAL,
            ],
            [
                'v=spf1 -all', '',
                [],
            ],
        ];
    }

    /**
     * @dataProvider feedValidateRawRecordCases
     */
    public function testValidateRawRecord(string $rawRecord, string $domain, array $expectedIssueCodes, ?int $minimumLevel = null): void
    {
        $issues = self::$validator->validateRawRecord($rawRecord, $domain, $minimumLevel);
        $this->checkIssues($issues, $expectedIssueCodes, $minimumLevel);
    }

    public function feedValidateRecordCases(): array
    {
        $decoder = new Decoder();

        return [
            [
                $decoder->getRecordFromTXT('v=spf1 -all'), '',
                [],
            ],
        ];
    }

    /**
     * @dataProvider feedValidateRecordCases
     */
    public function testValidateRecord(Record $record, string $domain, array $expectedIssueCodes, ?int $minimumLevel = null): void
    {
        $issues = self::$validator->validateRecord($record, $domain, $minimumLevel);
        $this->checkIssues($issues, $expectedIssueCodes, $minimumLevel);
    }

    public function feedGetLookupsForDomainCases(): array
    {
        return [
            [
                '',
                0,
            ],
            [
                'test.example.org',
                0,
            ],
            [
                'test.example.org',
                0,
                ['test.example.org' => ['v=spf1 mal formed!']],
            ],
            [
                'test1.example.org',
                4,
                [
                    'test1.example.org' => ['v=spf1 include:test2.example.org include:test3.example.org -all'],
                    'test2.example.org' => ['v=spf1 include:test4.example.org -all'],
                    'test3.example.org' => ['v=spf1 include:test4.example.org -all'],
                    'test4.example.org' => ['v=spf1 -all'],
                ],
            ],
            [
                'test.example.org',
                0,
                ['test.example.org' => ['v=spf1 include:_spf.%{d2} -all']],
            ],
            [
                'test1.example.org',
                11,
                [
                    'test1.example.org' => ['v=spf1 mx a include:test2.example.org include:test6.example.org include:test7.example.org ip4:1.2.3.4 ~all'],
                    'test2.example.org' => ['v=spf1 ip4:1.2.3.4 include:test3.example.org ~all'],
                    'test3.example.org' => ['v=spf1 ip4:1.2.3.4 include:test4.example.org ~all'],
                    'test4.example.org' => ['v=spf1 ip4:1.2.3.4 include:test5.example.org ~all'],
                    'test5.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test6.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test7.example.org' => ['v=spf1 include:test8.example.org include:test9.example.org include:test10.example.org ~all'],
                    'test8.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test9.example.org' => ['v=spf1 ~all'],
                    'test10.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                ],
            ],
            [
                'test1.example.org',
                10,
                [
                    'test1.example.org' => ['v=spf1 a include:test2.example.org include:test6.example.org include:test7.example.org ip4:1.2.3.4 ~all'],
                    'test2.example.org' => ['v=spf1 ip4:1.2.3.4 include:test3.example.org ~all'],
                    'test3.example.org' => ['v=spf1 ip4:1.2.3.4 include:test4.example.org ~all'],
                    'test4.example.org' => ['v=spf1 ip4:1.2.3.4 include:test5.example.org ~all'],
                    'test5.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test6.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test7.example.org' => ['v=spf1 include:test8.example.org include:test9.example.org include:test10.example.org ~all'],
                    'test8.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test9.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                    'test10.example.org' => ['v=spf1 ip4:1.2.3.4 ~all'],
                ],
            ],
        ];
    }

    /**
     * @dataProvider feedGetLookupsForDomainCases
     */
    public function testGetLookupsForDomain(string $domain, int $expectedLookups, array $txtRecords = []): void
    {
        self::$resolver->setFakeTXTRecords($txtRecords);
        $lookups = self::$validator->getLookupsForDomain($domain);
        $this->assertSame($expectedLookups, array_reduce($lookups, function ($total, $lookup) {
            return $total + $lookup->getLookupCount();
        }, 0));
    }

    public function feedGetLookupsForRawRecordCases(): array
    {
        return [
            [
                '', '',
                0,
            ],
            [
                'malformed', '',
                0,
            ],
            [
                'v=spf1 malformed', '',
                0,
            ],
            [
                'v=spf1 -all', '',
                0,
            ],
            [
                'v=spf1 include:test2.example.org include:test3.example.org -all', 'test1.example.org',
                4,
                [
                    'test2.example.org' => ['v=spf1 include:test4.example.org -all'],
                    'test3.example.org' => ['v=spf1 include:test4.example.org -all'],
                    'test4.example.org' => ['v=spf1 -all'],
                ],
            ],
        ];
    }

    /**
     * @dataProvider feedGetLookupsForRawRecordCases
     */
    public function testGetLookupsForRawRecord(string $rawRecord, string $domain, int $expectedLookups, array $txtRecords = []): void
    {
        self::$resolver->setFakeTXTRecords($txtRecords);
        $lookups = self::$validator->getLookupsForRawRecord($rawRecord, $domain);
        $this->assertSame($expectedLookups, array_reduce($lookups, function ($total, $lookup) {
            return $total + $lookup->getLookupCount();
        }, 0));
    }

    private function checkIssues(array $issues, array $expectedIssueCodes, ?int $minimumLevel)
    {
        $this->assertSameSize($expectedIssueCodes, $issues);
        foreach ($issues as $issue) {
            $this->assertInstanceOf(OnlineIssue::class, $issue);
            $this->assertContains($issue->getCode(), $expectedIssueCodes);
            $this->assertRegularExpression('/^\[(notice|warning|fatal)\] ./', (string) $issue);
            if ($minimumLevel === Issue::LEVEL_FATAL) {
                $this->assertRegularExpression('/^\[fatal\] ./', (string) $issue);
            }
        }
    }
}
