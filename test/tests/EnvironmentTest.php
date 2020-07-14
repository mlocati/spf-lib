<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use SPFLib\Check\Environment;
use SPFLib\Check\Result;
use SPFLib\Checker;
use SPFLib\DNS\Resolver;
use SPFLib\Test\FakeDnsResoler;
use SPFLib\Term\Mechanism;
use SPFLib\Exception\InvalidIPAddressException;
use IPLib\Factory;

class EnvironmentTest extends TestCase
{
    public function testEnvironment(): void
    {
        $environment = new Environment('', '');
        $this->assertNull($environment->getSMTPClientIP());
        $this->assertSame('', $environment->getMailFrom());
        $this->assertSame('', $environment->getHeloDomain());
        $this->assertSame(Environment::UNKNOWN_CHECKER_DOMAIN, $environment->getCheckerDomain());
        $error = null;
        try {
            new Environment('invalid.ip', '');
        } catch (InvalidIPAddressException $x) {
            $error = $x;
        }
        $this->assertNotNull($error);
        $environment = new Environment(Factory::addressFromString('0000::00:0:2'), '');
        $this->assertSame('::2', (string) $environment->getSMTPClientIP());
        $environment = new Environment('0000::00:0:fA', '');
        $this->assertSame('::fa', (string) $environment->getSMTPClientIP());
        $environment = new Environment('1.2.3.4', 'john@doe.com');
        $this->assertSame('doe.com', $environment->getHeloDomain());
        $environment = new Environment('1.2.3.4', 'john@doe.com', '');
        $this->assertSame('', $environment->getHeloDomain());
    }
}
