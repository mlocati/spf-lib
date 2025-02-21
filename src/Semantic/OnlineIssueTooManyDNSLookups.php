<?php

declare(strict_types=1);

namespace SPFLib\Semantic;

use SPFLib\OnlineDnsLookup;
use SPFLib\Record;

class OnlineIssueTooManyDNSLookups extends OnlineIssue
{
    /**
     * @var array<OnlineDnsLookup>
     */
    private array $dnsLookups;

    /**
     * Initialize the instance.
     *
     * @param string $dnsLookups the direct DNS lookups that are present in this record
     */
    public function __construct(
        array $dnsLookups,
        string $domain,
        string $txtRecord,
        ?Record $record,
        int $code,
        string $description,
        int $level
    ) {
        parent::__construct($domain, $txtRecord, $record, $code, $description, $level);
        $this->dnsLookups = $dnsLookups;
    }

    /**
     * Get all direct DNS lookups that are present in this record.
     *
     * @return array<OnlineDnsLookup>
     */
    public function getDnsLookups(): array
    {
        return $this->dnsLookups;
    }

    /**
     * Get the total amount of DNS lookups that are involved in this record.
     *
     * @return int
     */
    public function getTotalLookupCount(): int
    {
        return array_reduce($this->dnsLookups, function ($total, $dnsLookup) {
            return $total + $dnsLookup->getTotalLookupCount();
        }, 0);
    }
}
