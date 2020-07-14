<?php

declare(strict_types=1);

namespace SPFLib\Check;

use SPFLib\DNS\Resolver;
use SPFLib\Exception\TooManyDNSLookupsException;

/**
 * Class that holds the state of the check process.
 */
abstract class State
{
    /**
     * The maximum number of allowed DNS lookups.
     *
     * @var int
     *
     * @see https://tools.ietf.org/html/rfc7208#section-4.6.4
     */
    public const MAX_DNS_LOOKUPS = 10;

    /**
     * The environment being checked.
     *
     * @var \SPFLib\Check\Environment
     */
    private $environment;

    /**
     * The DNS resolver instance to be used for queries.
     *
     * @var \SPFLib\DNS\Resolver
     */
    private $resolver;

    /**
     * The domain name derived from the reverse lookup of the SMTP client IP.
     *
     * @var string
     */
    private $smtpClientIPDomain = '';

    /**
     * Cache the DNS reverse lookups already performed.
     *
     * @var array array keys are the string representation of an IP address, array values are the resolved addresses (empty string in case the reverse lookup failed)
     */
    private $reverseLookups = [];

    /**
     * The number of DNS queries already performed.
     *
     * @var int
     */
    private $dnsLookupsCount = 0;

    /**
     * Initialize the instance.
     *
     * @param \SPFLib\Check\Environment $environment $the environment
     * @param \SPFLib\DNS\Resolver $resolver the DNS resolver instance to be used for queries
     */
    public function __construct(Environment $environment, Resolver $resolver)
    {
        $this->environment = $environment;
        $this->resolver = $resolver;
    }

    public function __clone()
    {
        $this->environment = clone $this->getEnvoronment();
    }

    /**
     * Get the environment being checked.
     *
     * @return \SPFLib\Check\Environment
     */
    public function getEnvoronment(): Environment
    {
        return $this->environment;
    }

    /**
     * Get the sender email address currently being checked.
     *
     * @return string
     */
    abstract public function getSender(): string;

    /**
     * Get the local part of the sender email address currently being checked (that is, the part before '@').
     */
    public function getSenderLocalPart(): string
    {
        $sender = $this->getSender();
        $p = strpos($sender, '@');
        if ($p === false) {
            return '';
        }

        return substr($sender, 0, $p);
    }

    /**
     * Get the domain of the sender email address currently being checked (that is, the part after '@').
     */
    public function getSenderDomain(): string
    {
        $sender = $this->getSender();
        $p = strpos($sender, '@');
        if ($p === false) {
            return '';
        }

        return substr($sender, $p + 1);
    }

    /**
     * Get the domain name derived from the reverse lookup of the SMTP client IP.
     *
     * @throws \SPFLib\Exception\TooManyDNSLookupsException if too many DNS queries have been performed
     */
    public function getSMTPClientIPDomain(): string
    {
        $ip = $this->getEnvoronment()->getSMTPClientIP();
        if ($ip === null) {
            return '';
        }
        $key = (string) $ip;
        if (!isset($this->reverseLookups[$key])) {
            $this->countDNSLookup();
            $this->reverseLookups[$key] = $this->getResolver()->getDomainNameFromIPAddress($ip);
        }

        return $this->reverseLookups[$key];
    }

    /**
     * Reset the number of DNS queries already performed.
     *
     * @return self
     */
    public function resetDNSLookupsCount(): self
    {
        $this->dnsLookupsCount = 0;

        return $this;
    }

    /**
     * Count a DNS lookup and, if we are over the limit, throw a TooManyDNSLookupsException exception.
     */
    public function countDNSLookup(int $number = 1): void
    {
        $this->dnsLookupsCount += $number;
        if ($this->dnsLookupsCount > static::MAX_DNS_LOOKUPS) {
            throw new TooManyDNSLookupsException(static::MAX_DNS_LOOKUPS);
        }
    }

    /**
     * Get the DNS resolver instance to be used for queries.
     */
    protected function getResolver(): Resolver
    {
        return $this->resolver;
    }
}
