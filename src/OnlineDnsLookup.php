<?php

declare(strict_types=1);

namespace SPFLib;

/**
 * Information about a DNS lookup referenced in an SPF record.
 */
class OnlineDnsLookup
{
    /**
     * @var string
     */
    private $name;

    /**
     * @var string|null
     */
    private $record;

    /**
     * @var \SPFLib\OnlineDnsLookup[]
     */
    private $references = [];

    public function __construct(string $name, ?string $record = null)
    {
        $this->name = $name;
        $this->record = $record;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getRecord(): ?string
    {
        return $this->record;
    }

    /**
     * Add a recursive reference that is included within this lookup's record.
     *
     * @return $this
     */
    public function addReference(self $reference): self
    {
        $this->references[] = $reference;

        return $this;
    }

    /**
     * Get all recursive references that are included in this lookup's record.
     *
     * @return \SPFLib\OnlineDnsLookup[]
     */
    public function getReferences(): array
    {
        return $this->references[0];
    }

    /**
     * Get the total amount of recursive references present in this lookup's record.
     */
    public function getLookupCount(): int
    {
        return array_reduce($this->references, static function ($total, $reference) {
            return $total + $reference->getLookupCount();
        }, 1);
    }
}
