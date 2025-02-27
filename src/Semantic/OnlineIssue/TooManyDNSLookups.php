<?php

declare(strict_types=1);

namespace SPFLib\Semantic\OnlineIssue;

use SPFLib\Record;
use SPFLib\Semantic\OnlineIssue;

class TooManyDNSLookups extends OnlineIssue
{
    /**
     * @var \SPFLib\OnlineDnsLookup[]
     */
    private $dnsLookups;

    /**
     * Initialize the instance.
     *
     * @param \SPFLib\OnlineDnsLookup[] $dnsLookups the direct DNS lookups that are present in this record
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
     * @return \SPFLib\OnlineDnsLookup[]
     */
    public function getDnsLookups(): array
    {
        return $this->dnsLookups;
    }

    /**
     * Get the total amount of DNS lookups that are involved in this record.
     */
    public function getTotalLookupCount(): int
    {
        return array_reduce($this->dnsLookups, static function ($total, $dnsLookup) {
            return $total + $dnsLookup->getLookupCount();
        }, 0);
    }
}
