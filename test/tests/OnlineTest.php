<?php

declare(strict_types=1);

use SPFLib\Check\Environment;
use SPFLib\Check\Result;
use SPFLib\Checker;
use SPFLib\Decoder;
use SPFLib\Exception\DNSResolutionException;
use SPFLib\Test\TestCase;

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
        try {
            $record = $decoder->getRecordFromDomain($domain);
        } catch (DNSResolutionException $x) {
            $this->markTestSkipped("Error downloading the SPF record for {$domain}: {$x->getMessage()}");
        }
        if ($record === null) {
            $this->markTestSkipped("No SPF record downloaded for {$domain}");
        }
        $checker = new Checker();
        $result = $checker->check(new Environment('0.0.0.0', 'example.com'));
        $this->assertSame(Result::CODE_FAIL, $result->getCode());
    }
}
