<?php

declare(strict_types=1);

namespace SPFLib\DNS;

use MLocati\IDNA\DomainName;
use MLocati\IDNA\Exception\Exception as IDNAException;
use SPFLib\Exception\DNSResolutionException;

/**
 * A DNS resolver that uses the dns_get_record() PHP function.
 */
class StandardResolver implements Resolver
{
    /**
     * {@inheritdoc}
     *
     * @see \SPFLib\DNS\Resolver::getTXTRecords()
     */
    public function getTXTRecords(string $domain): array
    {
        if ($domain === '') {
            throw new DNSResolutionException('', 'No domain specified in ' . __FUNCTION__);
        }
        try {
            $actualDomain = DomainName::fromName($domain)->getPunycode();
        } catch (IDNAException $x) {
            throw new DNSResolutionException($domain, $x->getMessage());
        }
        $error = 'Unknown error';
        set_error_handler(
            static function ($errno, $errstr) use (&$error): void {
                $error = (string) $errstr;
                if ($error === '') {
                    $error = "Unknown error (code: {$errno})";
                }
            },
            -1
        );
        try {
            $records = dns_get_record($actualDomain, DNS_TXT);
        } finally {
            restore_error_handler();
        }
        if ($records === false) {
            throw new DNSResolutionException($domain, "Failed to get the TXT records for {$domain}: {$error}");
        }
        $result = [];
        foreach ($records as $record) {
            if (isset($record['txt'])) {
                $result[] = $record['txt'];
            }
        }

        return $result;
    }
}
