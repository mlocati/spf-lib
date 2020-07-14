<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use SPFLib\Check\Environment;
use SPFLib\Check\Result;
use SPFLib\Checker;
use SPFLib\DNS\Resolver;
use SPFLib\Term\Mechanism;
use SPFLib\Test\FakeDnsResoler;

class CheckerTest extends TestCase
{
    public function provideTestCases(): array
    {
        $emptyResolver = FakeDnsResoler::create();
        $resolver = FakeDnsResoler::create()
            ->setFakeTXTRecords([
                'mail1.from.com' => [
                    'v=spf1 ip4:10.20.30.40 ~ip6:0:0::3 -all exp=_exp.%{d}',
                ],
                'mail2.from.com' => [
                    'v=spf1 -all exp=_exp.%{d}',
                ],
                '_exp.mail1.from.com' => [
                    '%{l}%_access%_denied%_at%_%{o}%_via%_%{dr}',
                ],
                'recursive1.recdomain.com' => [
                    'v=spf1 include:recursive2.recdomain.%{d1}',
                ],
                'recursive2.recdomain.com' => [
                    'v=spf1 redirect=recursive1.%{d2}',
                ],
                'invalid.spf.com' => [
                    'v=spf1 redirect=domain1 redirect=domain2',
                ],
                'neutral.spf.com' => [
                    'v=spf1 ?all',
                ],
                'redirect.to.notexisting' => [
                    'v=spf1 redirect=not.existing.domain',
                ],
                'empty.spf.com' => [
                    'v=spf1',
                ],
                'a.default.spf.com' => [
                    'v=spf1 a',
                ],
                'a.cidr.spf.com' => [
                    'v=spf1 a/24//64',
                ],
            ])
            ->setFakeForwardLookups([
                'a.default.spf.com' => [
                    'a:b::c:d',
                ],
                'a.cidr.spf.com' => [
                    'a:b::c:d',
                ],
            ])
            ->setFakeMXRecords([
            ])
            ->setFakePTRRecords([
            ])
            ->setFakeReverseLookups([
            ])
        ;
        $environment = new Environment('10.20.30.40', 'john-doe.jr@mail.from.com', 'helo.ehlo.domain');

        return [
            // 0
            [
                $emptyResolver,
                $environment,
                Result::CODE_NONE,
                '',
                '',
                '/\bNo check/i',
                0,
            ],
            // 1
            [
                $emptyResolver,
                (clone $environment)->setSMTPClientIP(''),
                Result::CODE_NONE,
                '',
                '',
                '/ip address.+not speciified/i',
            ],
            // 2
            [
                $emptyResolver,
                (clone $environment)->setMailFrom(''),
                Result::CODE_NONE,
                '',
                '',
                '/MAIL FROM.+not valid/',
            ],
            // 3
            [
                $emptyResolver,
                (clone $environment)->setHeloDomain(''),
                Result::CODE_NONE,
                '',
                '',
                '/HELO.+EHLO.+not valid/',
                Checker::FLAG_CHECK_HELODOMAIN,
            ],
            // 4
            [
                $emptyResolver,
                $environment,
                Result::CODE_NONE,
                '',
                '',
                '/\bno spf\b.*\brecord.? found/i',
            ],
            // 5
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@mail1.from.com'),
                Result::CODE_PASS,
                Mechanism\Ip4Mechanism::class,
                '',
                '/^$/',
            ],
            // 6
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@mail1.from.com')->setSMTPClientIP('127.0.0.1'),
                Result::CODE_FAIL,
                Mechanism\AllMechanism::class,
                'john-doe.jr access denied at mail1.from.com via com.from.mail1._exp',
                '/^$/',
            ],
            // 7
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@mail1.from.com')->setSMTPClientIP('::3'),
                Result::CODE_SOFTFAIL,
                Mechanism\Ip6Mechanism::class,
                'john-doe.jr access denied at mail1.from.com via com.from.mail1._exp',
                '/^$/',
            ],
            // 8
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@recursive1.recdomain.com'),
                Result::CODE_ERROR_PERMANENT,
                '',
                '',
                '/Too many DNS lookups/i',
            ],
            // 9
            [
                $resolver,
                (clone $environment)->setSMTPClientIP('::a')->setMailFrom('john-doe.jr@mail1.from.com')->setHeloDomain('mail1.from.com'),
                Result::CODE_FAIL,
                Mechanism\AllMechanism::class,
                'postmaster access denied at mail1.from.com via com.from.mail1._exp',
                '/^$/',
                Checker::FLAG_CHECK_MAILFROADDRESS | Checker::FLAG_CHECK_HELODOMAIN,
            ],
            // 10
            [
                $resolver,
                (clone $environment)->setSMTPClientIP('::a')->setMailFrom('john-doe.jr@mail1.from.com')->setHeloDomain('mail2.from.com'),
                Result::CODE_FAIL,
                Mechanism\AllMechanism::class,
                '',
                "/no TXT records for '_exp.mail2.from.com/i",
                Checker::FLAG_CHECK_MAILFROADDRESS | Checker::FLAG_CHECK_HELODOMAIN,
            ],
            // 11
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@mail2.from.com')->setHeloDomain('mail1.from.com'),
                Result::CODE_PASS,
                Mechanism\Ip4Mechanism::class,
                '',
                '/^$/',
                Checker::FLAG_CHECK_MAILFROADDRESS | Checker::FLAG_CHECK_HELODOMAIN,
            ],
            // 12
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@invalid.spf.com'),
                Result::CODE_ERROR_PERMANENT,
                '',
                '',
                "/'redirect' modifier.+more than once/i",
            ],
            // 13
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@neutral.spf.com'),
                Result::CODE_NEUTRAL,
                Mechanism\AllMechanism::class,
                '',
                '/^$/',
            ],
            // 14
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@redirect.to.notexisting'),
                Result::CODE_ERROR_PERMANENT,
                '',
                '',
                "/redirect\b.+\b(didn't|did not) return a response code/i",
            ],
            // 15
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@empty.spf.com'),
                Result::CODE_NEUTRAL,
                '',
                '',
                "/\bNo mechanism.*\b(matched|found).*\bno\b.*\bredirect/i",
            ],
            // 16
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@recursive1.recdomain.com')->setHeloDomain('recursive2.recdomain.com'),
                Result::CODE_ERROR_PERMANENT,
                '',
                '',
                '/Too many DNS lookups/i',
                Checker::FLAG_CHECK_HELODOMAIN,
            ],
            // 17
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@a.default.spf.com'),
                Result::CODE_NEUTRAL,
                '',
                '',
                "/\bNo mechanism.*\b(matched|found).*\bno\b.*\bredirect/i",
            ],
            // 18
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@a.default.spf.com')->setSMTPClientIP('a:b::c:d'),
                Result::CODE_PASS,
                Mechanism\AMechanism::class,
                '',
                '/^$/i',
            ],
            // 19
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@a.default.spf.com')->setSMTPClientIP('a:b::c:1'),
                Result::CODE_NEUTRAL,
                '',
                '',
                "/\bNo mechanism.*\b(matched|found).*\bno\b.*\bredirect/i",
            ],
            // 19
            [
                $resolver,
                (clone $environment)->setMailFrom('john-doe.jr@a.cidr.spf.com')->setSMTPClientIP('a:b::c:1'),
                Result::CODE_PASS,
                Mechanism\AMechanism::class,
                '',
                '/^$/i',
            ],
        ];
    }

    /**
     * @dataProvider provideTestCases
     */
    public function testCase(
        Resolver $dnsResolver,
        Environment $environment,
        string $expectedResultCode,
        string $expectedMatchedMechanismClass,
        string $expectedFailMessage,
        string $expectedMessagesRegex,
        int $flags = Checker::FLAG_CHECK_MAILFROADDRESS
    ): void {
        $checker = new Checker($dnsResolver);
        $actualResult = $checker->check($environment, $flags);
        $this->assertSame($expectedResultCode, $actualResult->getCode());
        $this->assertSame($expectedFailMessage, $actualResult->getFailExplanation());
        if ($expectedMatchedMechanismClass === '') {
            $this->assertNull($actualResult->getMatchedMechanism());
        } else {
            $this->assertInstanceOf($expectedMatchedMechanismClass, $actualResult->getMatchedMechanism());
        }
        $this->assertRegExp($expectedMessagesRegex, implode("\n", $actualResult->getMessages()));
    }
}
