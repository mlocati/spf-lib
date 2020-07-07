<?php

declare(strict_types=1);

namespace SPFLib\Term\Mechanism;

use SPFLib\Term\Mechanism;

/**
 * Class that represents the "include" mechanism.
 *
 * @see https://tools.ietf.org/html/rfc7208#section-5.2
 */
class IncludeMechanism extends Mechanism
{
    /**
     * The handle that identifies this mechanism.
     *
     * @var string
     */
    public const HANDLE = 'include';

    /**
     * @var string
     */
    private $domainSpec;

    /**
     * Initialize the instance.
     *
     * @param string $qualifier the qualifier of this mechanism (the value of one of the Mechanism::QUALIFIER_... constants)
     */
    public function __construct(string $qualifier, string $domainSpec)
    {
        parent::__construct($qualifier);
        $this->domainSpec = $domainSpec;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\Term::__toString()
     */
    public function __toString(): string
    {
        return $this->getQualifier(true) . static::HANDLE . ':' . $this->getDomainSpec();
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
}
