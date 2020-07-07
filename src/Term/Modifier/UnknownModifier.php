<?php

declare(strict_types=1);

namespace SPFLib\Term\Modifier;

use SPFLib\Term\Modifier;

/**
 * Class that represents the "unknown" modifier.
 *
 * @see https://tools.ietf.org/html/rfc7208#section-12
 */
class UnknownModifier extends Modifier
{
    /**
     * @var string
     */
    private $name;

    /**
     * @var string
     */
    private $value;

    /**
     * Initialize the instance.
     */
    public function __construct(string $name, string $value)
    {
        $this->name = $name;
        $this->value = $value;
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\Term::__toString()
     */
    public function __toString(): string
    {
        return $this->getName() . '=' . $this->getValue();
    }

    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\Term\Modifier::getName()
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Get the name of the modifier (the part after '=').
     */
    public function getValue(): string
    {
        return $this->value;
    }
}
