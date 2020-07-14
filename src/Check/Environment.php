<?php

declare(strict_types=1);

namespace SPFLib\Check;

use Closure;
use IPLib\Address\AddressInterface;
use IPLib\Factory;
use SPFLib\Exception\InvalidIPAddressException;

/**
 * Class that holds the environment values to be used for the check.
 */
class Environment
{
    /**
     * The value to be used for the checker domain.
     *
     * @var string
     */
    public const UNKNOWN_CHECKER_DOMAIN = 'unknown';

    /**
     * The IP address of the SMTP client that is emitting the email.
     *
     * @var \IPLib\Address\AddressInterface|null
     */
    private $smtpClientIP;

    /**
     * The email address specified in the "MAIL FROM" MTA command.
     *
     * @var string
     */
    private $mailFrom;

    /**
     * The domain name that was provided to the SMTP server via the HELO or EHLO SMTP verb.
     *
     * @var string
     */
    private $heloDomain;

    /**
     * The closure that fetches the domain name derived from the reverse lookup of the SMTP client IP.
     *
     * @var \Closure|null
     */
    private $smtpClientIPDomainGetter;

    /**
     * The name of the receiving MTA.
     * This SHOULD be a fully qualified domain name, but if one does not exist (as when the checking is done by a Mail User Agent (MUA))
     * or if policy restrictions dictate otherwise, the word "unknown" SHOULD be substituted.
     * The domain name can be different from the name found in the MX record that the client MTA used to locate the receiving MTA.
     *
     * @var string
     */
    private $checkerDomain = '';

    /**
     * Initialize the instance.
     *
     * @param \IPLib\Address\AddressInterface|string|null $clientIP the IP address of the SMTP client that is emitting the email
     * @param string $mailFrom email the address specified in the "MAIL FROM" MTA command
     * @param string|null $heloDomain the domain specified in the "HELO" (or "EHLO") MTA command (if NULL we'll use the domain of $mailFrom)
     *
     * @throws \SPFLib\Exception\InvalidIPAddressException if $clientIP is not empty and doesn't represent a valid IP address
     */
    public function __construct($clientIP, string $mailFrom, ?string $heloDomain = null)
    {
        if ($heloDomain === null) {
            $atPosition = strpos($mailFrom, '@');
            $heloDomain = $atPosition === false ? '' : substr($mailFrom, $atPosition + 1);
        }
        $this
            ->setSMTPClientIP($clientIP)
            ->setMailFrom($mailFrom)
            ->setHeloDomain($heloDomain)
            ->setCheckerDomain(static::UNKNOWN_CHECKER_DOMAIN)
        ;
    }

    /**
     * Set the IP address of the SMTP client that is emitting the email.
     *
     * @param \IPLib\Address\AddressInterface|string|null $value
     *
     * @throws \SPFLib\Exception\InvalidIPAddressException if $value is not empty and doesn't represent a valid IP address
     *
     * @return $this
     */
    public function setSMTPClientIP($value): self
    {
        if ($value === null || $value === '') {
            $this->smtpClientIP = null;
        } elseif ($value instanceof AddressInterface) {
            $this->smtpClientIP = $value;
        } else {
            $address = Factory::addressFromString($value);
            if ($address === null) {
                throw new InvalidIPAddressException($value);
            }
            $this->smtpClientIP = $address;
        }

        return $this;
    }

    /**
     * Get the IP address of the SMTP client that is emitting the email.
     */
    public function getSMTPClientIP(): ?AddressInterface
    {
        return $this->smtpClientIP;
    }

    /**
     * Set the email address specified in the "MAIL FROM" MTA command.
     *
     * @return $this
     */
    public function setMailFrom(string $value): self
    {
        $this->mailFrom = $value;

        return $this;
    }

    /**
     * Get the email address specified in the "MAIL FROM" MTA command.
     */
    public function getMailFrom(): string
    {
        return $this->mailFrom;
    }

    /**
     * Get the domain after the '@' character of the email address specified in the "MAIL FROM" MTA command.
     */
    public function getMailFromDomain(): string
    {
        $mailFrom = $this->getMailFrom();
        $atPosition = strpos($mailFrom, '@');

        return $atPosition === false ? '' : substr($mailFrom, $atPosition + 1);
    }

    /**
     * Set the domain name that was provided to the SMTP server via the HELO or EHLO SMTP verb.
     *
     * @return $this
     */
    public function setHeloDomain(string $value): self
    {
        $this->heloDomain = $value;

        return $this;
    }

    /**
     * Get the domain name that was provided to the SMTP server via the HELO or EHLO SMTP verb.
     */
    public function getHeloDomain(): string
    {
        return $this->heloDomain;
    }

    /**
     * Set the name of the receiving MTA.
     * This SHOULD be a fully qualified domain name, but if one does not exist (as when the checking is done by a Mail User Agent (MUA))
     * or if policy restrictions dictate otherwise, the word "unknown" SHOULD be substituted.
     * The domain name can be different from the name found in the MX record that the client MTA used to locate the receiving MTA.
     *
     * @return $this
     */
    public function setCheckerDomain(string $value): self
    {
        $this->checkerDomain = $value;

        return $this;
    }

    /**
     * Get the name of the receiving MTA.
     */
    public function getCheckerDomain(): string
    {
        return $this->checkerDomain;
    }
}
