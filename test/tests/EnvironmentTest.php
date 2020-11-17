<?php

declare(strict_types=1);

use IPLib\Factory;
use SPFLib\Check\Environment;
use SPFLib\Exception\InvalidIPAddressException;
use SPFLib\Test\TestCase;

class EnvironmentTest extends TestCase
{
    public function testEnvironment(): void
    {
        $environment = new Environment('', '');
        $this->assertNull($environment->getClientIP());
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
        $this->assertSame('::2', (string) $environment->getClientIP());
        $environment = new Environment('0000::00:0:fA', '');
        $this->assertSame('::fa', (string) $environment->getClientIP());
    }
}
