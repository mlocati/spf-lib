<?php

declare(strict_types=1);

namespace SPFLib;

/**
 * Information about a DNS lookup referenced in an SPF record.
 */
class OnlineDnsLookup
{
    private string $name;
    private ?string $record;
    private array $references = [];

    public function __construct(string $name, ?string $record = null)
    {
        $this->name = $name;
        $this->record = $record;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getRecord(): string
    {
        return $this->record;
    }

    /**
     * Add a recursive reference that is included within this lookup's record.
     *
     * @param OnlineDnsLookup $reference
     */
    public function addReference(OnlineDnsLookup $reference): void
    {
        $this->references[] = $reference;
    }

    /**
     * Get all recursive references that are included in this lookup's record.
     *
     * @return array<self>
     */
    public function getReferences(): array
    {
        return $this->references;
    }

    /**
     * Get the total amount of recursive references present in this lookup's record.
     *
     * @return int
     */
    public function getLookupCount(): int
    {
        return array_reduce($this->references, function ($total, $reference) {
            return $total + $reference->getLookupCount();
        }, 1);
    }
}
