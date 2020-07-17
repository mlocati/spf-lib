<?php

declare(strict_types=1);

namespace SPFLib\Test;

use IPLib\Address\AddressInterface;
use IPLib\Factory;
use SPFLib\DNS\Resolver;
use Throwable;

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
        $this->fakeTXTRecords = array_change_key_case($value);

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getTXTRecords()
     */
    public function getTXTRecords(string $domain): array
    {
        $result = $this->fakeTXTRecords[strtolower($domain)] ?? [];
        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }

    /**
     * @return $this
     */
    public function setFakeForwardLookups(array $value): self
    {
        $this->fakeForwardLookups = array_change_key_case($value);

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getIPAddressesFromDomainName()
     */
    public function getIPAddressesFromDomainName(string $domain): array
    {
        $items = $this->fakeForwardLookups[strtolower($domain)] ?? [];
        if ($items instanceof Throwable) {
            throw $items;
        }
        $result = [];
        foreach ($items as $ip) {
            $result[] = Factory::addressFromString($ip);
        }

        return $result;
    }

    /**
     * @return $this
     */
    public function setFakeMXRecords(array $value): self
    {
        $this->fakeMXRecords = array_change_key_case($value);

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getMXRecords()
     */
    public function getMXRecords(string $domain): array
    {
        $result = $this->fakeMXRecords[strtolower($domain)] ?? [];
        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }

    /**
     * @return $this
     */
    public function setFakePTRRecords(array $value): self
    {
        $this->fakePTRRecords = array_change_key_case($value);

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getPTRRecords()
     */
    public function getPTRRecords(string $domain): array
    {
        $result = $this->fakePTRRecords[$domain] ?? [];
        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }

    /**
     * @return $this
     */
    public function setFakeReverseLookups(array $value): self
    {
        $this->fakeReverseLookups = array_change_key_case($value);

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getDomainNameFromIPAddress()
     */
    public function getDomainNameFromIPAddress(AddressInterface $ip): string
    {
        $result = $this->fakeReverseLookups[(string) $ip] ?? [];
        if ($result instanceof Throwable) {
            throw $result;
        }
        if ($result === []) {
            return '';
        }

        return $result;
    }
}
