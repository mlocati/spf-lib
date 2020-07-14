<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use SPFLib\Check\Environment;
use SPFLib\Check\Result;
use SPFLib\Checker;
use SPFLib\Decoder;

class OnlineTest extends TestCase
{
    public function provideTestCases(): array
    {
        return [
            ['facebook.com'],
            ['gmail.com'],
            ['amazon.com'],
        ];
    }

    /**
     * @dataProvider provideTestCases
     */
    public function testCase(string $domain): void
    {
        $decoder = new Decoder();
        $record = $decoder->getRecordFromDomain($domain);
        $this->assertNotNull($record);
        $checker = new Checker();
        $result = $checker->check(new Environment('0.0.0.0', 'john-doe@example.com'));
        $this->assertSame(Result::CODE_FAIL, $result->getCode());
    }
}
