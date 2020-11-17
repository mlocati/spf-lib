<?php

declare(strict_types=1);

use SPFLib\DNS\StandardResolver;
use SPFLib\Exception\DNSResolutionException;
use SPFLib\Test\TestCase;

class DNSResolverTest extends TestCase
{
    /**
     * @var \SPFLib\DNS\Resolver
     */
    protected static $resolver;

    /**
     * {@inheritdoc}
     *
     * @see \PHPUnit\Framework\TestCase::setUpBeforeClass()
     */
    public static function setUpBeforeClass(): void
    {
        self::$resolver = new StandardResolver();
    }

    public function testSuccess(): void
    {
        $txts = self::$resolver->getTXTRecords('gmail.com');
        $this->assertNotSame([], $txts);
    }

    public function provideInvalidDomainNames(): array
    {
        return [
            [''],
            [' '],
        ];
    }

    /**
     * @dataProvider provideInvalidDomainNames
     */
    public function testFail(string $invalidDomain): void
    {
        $error = null;
        try {
            self::$resolver->getTXTRecords($invalidDomain);
        } catch (Throwable $x) {
            $error = $x;
        }
        $this->assertInstanceOf(DNSResolutionException::class, $error);
        $this->assertSame($invalidDomain, $error->getDomain());
    }
}
