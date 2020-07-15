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
        $environment = new Environment('10.20.30.40', 'helo.ehlo.domain', 'john-doe.jr@mail.from.com');

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
                new Environment('', $environment->getHeloDomain(), $environment->getMailFrom(), $environment->getCheckerDomain()),
                Result::CODE_NONE,
                '',
                '',
                '/ip address.+not speciified/i',
            ],
            // 2
            [
                $emptyResolver,
                new Environment($environment->getClientIP(), $environment->getHeloDomain(), '', $environment->getCheckerDomain()),
                Result::CODE_NONE,
                '',
                '',
                '/MAIL FROM.+not valid/',
            ],
            // 3
            [
                $emptyResolver,
                new Environment($environment->getClientIP(), '', $environment->getMailFrom(), $environment->getCheckerDomain()),
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
                new Environment($environment->getClientIP(), $environment->getHeloDomain(), 'john-doe.jr@mail1.from.com', $environment->getCheckerDomain()),
                Result::CODE_PASS,
                Mechanism\Ip4Mechanism::class,
                '',
                '/^$/',
            ],
            // 6
            [
                $resolver,
                new Environment('127.0.0.1', $environment->getHeloDomain(), 'john-doe.jr@mail1.from.com', $environment->getCheckerDomain()),
                Result::CODE_FAIL,
                Mechanism\AllMechanism::class,
                'john-doe.jr access denied at mail1.from.com via com.from.mail1._exp',
                '/^$/',
            ],
            // 7
            [
                $resolver,
                new Environment('::3', $environment->getHeloDomain(), 'john-doe.jr@mail1.from.com', $environment->getCheckerDomain()),
                Result::CODE_SOFTFAIL,
                Mechanism\Ip6Mechanism::class,
                'john-doe.jr access denied at mail1.from.com via com.from.mail1._exp',
                '/^$/',
            ],
            // 8
            [
                $resolver,
                new Environment($environment->getClientIP(), $environment->getHeloDomain(), 'john-doe.jr@recursive1.recdomain.com', $environment->getCheckerDomain()),
                Result::CODE_ERROR_PERMANENT,
                '',
                '',
                '/Too many DNS lookups/i',
            ],
            // 9
            [
                $resolver,
                new Environment('::a', 'mail1.from.com', 'john-doe.jr@mail1.from.com', $environment->getCheckerDomain()),
                Result::CODE_FAIL,
                Mechanism\AllMechanism::class,
                'postmaster access denied at mail1.from.com via com.from.mail1._exp',
                '/^$/',
                Checker::FLAG_CHECK_MAILFROADDRESS | Checker::FLAG_CHECK_HELODOMAIN,
            ],
            // 10
            [
                $resolver,
                new Environment('::a', 'mail2.from.com', 'john-doe.jr@mail1.from.com', $environment->getCheckerDomain()),
                Result::CODE_FAIL,
                Mechanism\AllMechanism::class,
                '',
                "/no TXT records for '_exp.mail2.from.com/i",
                Checker::FLAG_CHECK_MAILFROADDRESS | Checker::FLAG_CHECK_HELODOMAIN,
            ],
            // 11
            [
                $resolver,
                new Environment($environment->getClientIP(), 'mail1.from.com', 'john-doe.jr@mail2.from.com', $environment->getCheckerDomain()),
                Result::CODE_PASS,
                Mechanism\Ip4Mechanism::class,
                '',
                '/^$/',
                Checker::FLAG_CHECK_MAILFROADDRESS | Checker::FLAG_CHECK_HELODOMAIN,
            ],
            // 12
            [
                $resolver,
                new Environment($environment->getClientIP(), $environment->getHeloDomain(), 'john-doe.jr@invalid.spf.com', $environment->getCheckerDomain()),
                Result::CODE_ERROR_PERMANENT,
                '',
                '',
                "/'redirect' modifier.+more than once/i",
            ],
            // 13
            [
                $resolver,
                new Environment($environment->getClientIP(), $environment->getHeloDomain(), 'john-doe.jr@neutral.spf.com', $environment->getCheckerDomain()),
                Result::CODE_NEUTRAL,
                Mechanism\AllMechanism::class,
                '',
                '/^$/',
            ],
            // 14
            [
                $resolver,
                new Environment($environment->getClientIP(), $environment->getHeloDomain(), 'john-doe.jr@redirect.to.notexisting', $environment->getCheckerDomain()),
                Result::CODE_ERROR_PERMANENT,
                '',
                '',
                "/redirect\b.+\b(didn't|did not) return a response code/i",
            ],
            // 15
            [
                $resolver,
                new Environment($environment->getClientIP(), $environment->getHeloDomain(), 'john-doe.jr@empty.spf.com', $environment->getCheckerDomain()),
                Result::CODE_NEUTRAL,
                '',
                '',
                "/\bNo mechanism.*\b(matched|found).*\bno\b.*\bredirect/i",
            ],
            // 16
            [
                $resolver,
                new Environment($environment->getClientIP(), 'recursive2.recdomain.com', 'john-doe.jr@recursive1.recdomain.com', $environment->getCheckerDomain()),
                Result::CODE_ERROR_PERMANENT,
                '',
                '',
                '/Too many DNS lookups/i',
                Checker::FLAG_CHECK_HELODOMAIN,
            ],
            // 17
            [
                $resolver,
                new Environment($environment->getClientIP(), $environment->getHeloDomain(), 'john-doe.jr@a.default.spf.com', $environment->getCheckerDomain()),
                Result::CODE_NEUTRAL,
                '',
                '',
                "/\bNo mechanism.*\b(matched|found).*\bno\b.*\bredirect/i",
            ],
            // 18
            [
                $resolver,
                new Environment('a:b::c:d', $environment->getHeloDomain(), 'john-doe.jr@a.default.spf.com', $environment->getCheckerDomain()),
                Result::CODE_PASS,
                Mechanism\AMechanism::class,
                '',
                '/^$/i',
            ],
            // 19
            [
                $resolver,
                new Environment('a:b::c:1', $environment->getHeloDomain(), 'john-doe.jr@a.default.spf.com', $environment->getCheckerDomain()),
                Result::CODE_NEUTRAL,
                '',
                '',
                "/\bNo mechanism.*\b(matched|found).*\bno\b.*\bredirect/i",
            ],
            // 19
            [
                $resolver,
                new Environment('a:b::c:1', $environment->getHeloDomain(), 'john-doe.jr@a.cidr.spf.com', $environment->getCheckerDomain()),
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
