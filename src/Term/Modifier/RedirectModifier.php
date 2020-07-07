<?php

declare(strict_types=1);

namespace SPFLib\Term\Modifier;

use SPFLib\Term\Modifier;

/**
 * Class that represents the "redirect" modifier.
 *
 * @see https://tools.ietf.org/html/rfc7208#section-6.1
 */
class RedirectModifier extends Modifier
{
    /**
     * The handle that identifies this modifier.
     *
     * @var string
     */
    public const HANDLE = 'redirect';

    /**
     * @var string
     */
    private $domainSpec;

    /**
     * Initialize the instance.
     */
    public function __construct(string $domainSpec)
    {
        $this->domainSpec = $domainSpec;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\Term::__toString()
     */
    public function __toString(): string
    {
        return static::HANDLE . '=' . $this->getDomainSpec();
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\Term\Modifier::getName()
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
