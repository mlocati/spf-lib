<?php

declare(strict_types=1);

use SPFLib\Decoder;
use SPFLib\Term\Modifier;
use SPFLib\Test\TestCase;

class CloneTest extends TestCase
{
    public function testClone(): void
    {
        $decoder = new Decoder();
        $record = $decoder->getRecordFromTXT('v=spf1 a:foo1.bar exists:foo2.bar include:foo3.bar mx:foo4.bar ptr:foo5.bar exp=foo5.bar redirect=foo6.bar unknown=foo7.bar');
        $clonedRecord = clone $record;
        $terms = $record->getTerms();
        $clonedTerms = $clonedRecord->getTerms();
        $this->assertEquals($record, $clonedRecord);
        $this->assertEquals($terms, $clonedTerms);
        foreach ($terms as $index => $term) {
            $clonedTerm = $clonedTerms[$index];
            $this->assertNotSame($term, $clonedTerm);
            if ($term instanceof Modifier\UnknownModifier) {
                $this->assertNotSame($term->getValue(), $clonedTerm->getValue());
            } else {
                $this->assertNotSame($term->getDomainSpec(), $clonedTerm->getDomainSpec());
            }
        }
    }
}
