<?php

declare(strict_types=1);

namespace SPFLib\Test;

use IPLib\Address\AddressInterface;
use IPLib\Factory;
use SPFLib\DNS\Resolver;

class FakeDnsResoler implements Resolver
{
    /**
     * @var array
     */
    private $fakeTXTRecords = [];

    /**
     * @var array
     */
    private $fakeForwardLookups = [];

    /**
     * @var array
     */
    private $fakeMXRecords = [];

    /**
     * @var array
     */
    private $fakePTRRecords = [];

    /**
     * @var array
     */
    private $fakeReverseLookups = [];

    private function __construct()
    {
    }

    public static function create(): self
    {
        return new self();
    }

    /**
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
        return $this->fakeTXTRecords[$domain] ?? [];
    }

    /**
     * @return $this
     */
    public function setFakeForwardLookups(array $value): self
    {
        $this->fakeForwardLookups = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getIPAddressesFromDomainName()
     */
    public function getIPAddressesFromDomainName(string $domain): array
    {
        $result = [];
        foreach ($this->fakeForwardLookups[$domain] ?? [] as $ip) {
            $result[] = Factory::addressFromString($ip);
        }

        return $result;
    }

    /**
     * @return $this
     */
    public function setFakeMXRecords(array $value): self
    {
        $this->fakeMXRecords = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getMXRecords()
     */
    public function getMXRecords(string $domain): array
    {
        return $this->fakeMXRecords[$domain] ?? [];
    }

    /**
     * @return $this
     */
    public function setFakePTRRecords(array $value): self
    {
        $this->fakePTRRecords = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getPTRRecords()
     */
    public function getPTRRecords(AddressInterface $ip): array
    {
        return $this->fakePTRRecords[(string) $ip] ?? [];
    }

    /**
     * @return $this
     */
    public function setFakeReverseLookups(array $value): self
    {
        $this->fakeReverseLookups = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getDomainNameFromIPAddress()
     */
    public function getDomainNameFromIPAddress(AddressInterface $ip): string
    {
        return $this->fakeReverseLookups[(string) $ip] ?? '';
    }
}
