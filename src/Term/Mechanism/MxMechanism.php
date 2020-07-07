<?php

declare(strict_types=1);

namespace SPFLib\Term\Mechanism;

use SPFLib\Term\Mechanism;

/**
 * Class that represents the "mx" mechanism.
 *
 * @see https://tools.ietf.org/html/rfc7208#section-5.4
 */
class MxMechanism extends Mechanism
{
    /**
     * The handle that identifies this mechanism.
     *
     * @var string
     */
    public const HANDLE = 'mx';

    /**
     * @var string
     */
    private $domainSpec;

    /**
     * @var int
     */
    private $ip4CidrLength;

    /**
     * @var int
     */
    private $ip6CidrLength;

    /**
     * Initialize the instance.
     *
     * @param string $qualifier the qualifier of this mechanism (the value of one of the Mechanism::QUALIFIER_... constants)
     */
    public function __construct(string $qualifier, string $domainSpec = '', ?int $ip4CidrLength = null, ?int $ip6CidrLength = null)
    {
        parent::__construct($qualifier);
        $this->domainSpec = $domainSpec;
        $this->ip4CidrLength = $ip4CidrLength === null ? 32 : $ip4CidrLength;
        $this->ip6CidrLength = $ip6CidrLength === null ? 128 : $ip6CidrLength;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\Term::__toString()
     */
    public function __toString(): string
    {
        $result = $this->getQualifier(true) . static::HANDLE;
        $domainSpec = $this->getDomainSpec();
        if ($domainSpec !== '') {
            $result .= ':' . $this->getDomainSpec();
        }
        $ip4CidrLength = $this->getIp4CidrLength();
        if ($ip4CidrLength !== 32) {
            $result .= "/{$ip4CidrLength}";
        }
        $ip6CidrLength = $this->getIp6CidrLength();
        if ($ip6CidrLength !== 128) {
            $result .= "//{$ip6CidrLength}";
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\Term\Mechanism::getName()
     */
    public function getName(): string
    {
        return static::HANDLE;
    }

    public function getDomainSpec(): string
    {
        return $this->domainSpec;
    }

    public function getIp4CidrLength(): int
    {
        return $this->ip4CidrLength;
    }

    public function getIp6CidrLength(): int
    {
        return $this->ip6CidrLength;
    }
}
