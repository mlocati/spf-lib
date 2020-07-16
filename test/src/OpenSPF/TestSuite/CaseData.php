<?php

declare(strict_types=1);

namespace SPFLib\Test\OpenSPF\TestSuite;

class CaseData
{
    /**
     * @var string
     */
    private $id;

    /**
     * @var string
     */
    private $description;

    /**
     * @var string
     */
    private $comment;

    /**
     * @var string[]
     */
    private $specifications;

    /**
     * @var string
     */
    private $helo;

    /**
     * @var string
     */
    private $host;

    /**
     * @var string
     */
    private $mailFrom;

    /**
     * @var string[]
     */
    private $allowedResults;

    /**
     * @var string
     */
    private $explanation;

    /**
     * @param string[] $allowedResults
     */
    public function __construct(string $id, string $description, string $comment, array $specifications, string $helo, string $host, string $mailFrom, array $allowedResults, string $explanation)
    {
        $this->id = $id;
        $this->description = $description;
        $this->comment = $comment;
        $this->specifications = $specifications;
        $this->helo = $helo;
        $this->host = $host;
        $this->mailFrom = $mailFrom;
        $this->allowedResults = $allowedResults;
        $this->explanation = $explanation;
    }

    public function getID(): string
    {
        return $this->id;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getComment(): string
    {
        return $this->comment;
    }

    /**
     * @return string[]
     */
    public function getSpecifications(): array
    {
        return $this->spec;
    }

    public function getHelo(): string
    {
        return $this->helo;
    }

    public function getHost(): string
    {
        return $this->host;
    }

    public function getMailFrom(): string
    {
        return $this->mailFrom;
    }

    /**
     * @return string[]
     */
    public function getAllowedResults(): array
    {
        return $this->allowedResults;
    }

    public function getExplanation(): string
    {
        return $this->explanation;
    }
}
