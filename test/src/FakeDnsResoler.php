<?php

declare(strict_types=1);

namespace SPFLib\Test;

use SPFLib\DNS\Resolver;

class FakeDnsResoler implements Resolver
{
    /**
     * @var string[]
     */
    private $fakeTXTRecords;

    /**
     * @param string[] $fakeTXTRecords
     */
    public function __construct(array $fakeTXTRecords = [])
    {
        $this->setFakeTXTRecords($fakeTXTRecords);
    }

    /**
     * @param string[] $value
     *
     * @return $this
     */
    public function setFakeTXTRecords(array $value): self
    {
        $this->fakeTXTRecords = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getTXTRecords()
     */
    public function getTXTRecords(string $domain): array
    {
        return $this->fakeTXTRecords;
    }
}
