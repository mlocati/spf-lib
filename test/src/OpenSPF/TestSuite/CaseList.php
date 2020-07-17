<?php

declare(strict_types=1);

namespace SPFLib\Test\OpenSPF\TestSuite;

use SPFLib\DNS\Resolver;

class CaseList
{
    /**
     * @var string
     */
    private $dataKey;

    /**
     * @var string
     */
    private $description;

    /**
     * @var string
     */
    private $comment;

    /**
     * @var \SPFLib\DNS\Resolver
     */
    private $dnsResolver;

    /**
     * @var \SPFLib\Test\OpenSPF\TestSuite\CaseData[]
     */
    private $cases = [];

    public function __construct(string $dataKey, string $description, string $comment, Resolver $dnsResolver)
    {
        $this->dataKey = $dataKey;
        $this->description = $description;
        $this->comment = $comment;
        $this->dnsResolver = $dnsResolver;
    }

    public function getDataKey(): string
    {
        return $this->dataKey;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getComment(): string
    {
        return $this->comment;
    }

    public function getDNSResolver(): Resolver
    {
        return $this->dnsResolver;
    }

    /**
     * @return $this
     */
    public function addCase(CaseData $case): self
    {
        $this->cases[] = $case;

        return $this;
    }

    /**
     * @return \SPFLib\Test\OpenSPF\TestSuite\CaseData
     */
    public function getCasesData(): array
    {
        return $this->cases;
    }
}
