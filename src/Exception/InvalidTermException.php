<?php

declare(strict_types=1);

namespace SPFLib\Exception;

use SPFLib\Exception;

/**
 * Exception thrown when an SPF record contains an unrecognized term.
 */
class InvalidTermException extends Exception
{
    /**
     * The term that wasn't recognized.
     *
     * @var string
     */
    private $term;

    /**
     * Initialize the instance.
     *
     * @param string $term the term that wasn't recognized
     */
    public function __construct(string $term)
    {
        parent::__construct("The SPF record contains an unrecognized term: {$term}");
        $this->term = $term;
    }

    /**
     * Get the term that wasn't recognized.
     */
    public function getTerm(): string
    {
        return $this->term;
    }
}
