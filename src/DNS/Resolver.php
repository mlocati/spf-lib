<?php

declare(strict_types=1);

namespace SPFLib\DNS;

/**
 * Interface that DNS record resolvers must implement.
 */
interface Resolver
{
    /**
     * Get the TXT records for a domain.
     *
     * @throws \SPFLib\Exception\DNSResolutionException in case of DNS resolution errors
     *
     * @return string[]
     */
    public function getTXTRecords(string $domain): array;
}
