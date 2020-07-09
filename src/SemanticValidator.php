<?php

declare(strict_types=1);

namespace SPFLib;

use SPFLib\Semantic\Issue;
use SPFLib\Term\Mechanism;
use SPFLib\Term\Modifier;

/**
 * An RFC7208-compliant semantic validator.
 *
 * @see https://tools.ietf.org/html/rfc7208
 */
class SemanticValidator
{
    /**
     * Get all the semantical warnings of an SPF record.
     *
     * @param \SPFLib\Record $record the record to be checked
     * @param int|null $minimumLevel the minimum level of the issues (the value of one of the Issue::LEVEL_... constants)
     *
     * @return \SPFLib\Semantic\Issue[] The warnings
     */
    public function validate(Record $record, ?int $minimumLevel = null): array
    {
        $issues = array_merge(
            $this->checkMaxDNSLookups($record),
            $this->checkAllIsLastMechanism($record),
            $this->checkAllAndRedirect($record),
            $this->checkNoPtr($record),
            $this->checkModifiersPosition($record),
            $this->checkModifiersUniqueness($record),
            $this->checkUnknownModifiers($record)
        );
        if ($minimumLevel !== null) {
            $issues = array_values(
                array_filter(
                    $issues,
                    static function (Issue $issue) use ($minimumLevel): bool {
                        return $issue->getLevel() >= $minimumLevel;
                    }
                )
            );
        }

        return $issues;
    }

    /**
     * @return \SPFLib\Semantic\Issue[]
     *
     * @see https://tools.ietf.org/html/rfc7208#section-4.6.4
     */
    protected function checkMaxDNSLookups(Record $record): array
    {
        $mechanisms = [
            Mechanism\IncludeMechanism::HANDLE,
            Mechanism\AMechanism::HANDLE,
            Mechanism\MxMechanism::HANDLE,
            Mechanism\PtrMechanism::HANDLE,
            Mechanism\ExistsMechanism::HANDLE,
        ];
        $modifiers = [
            Modifier\RedirectModifier::HANDLE,
        ];
        $count = 0;
        foreach ($record->getMechanisms() as $mechanism) {
            if (in_array($mechanism->getName(), $mechanisms, true)) {
                $count++;
            }
        }
        foreach ($record->getModifiers() as $modifier) {
            if (in_array($modifier->getName(), $modifiers, true)) {
                $count++;
            }
        }
        if ($count <= 10) {
            return [];
        }

        return [
            new Issue(
                $record,
                Issue::CODE_TOO_MANY_DNS_LOOKUPS,
                "The total number of the '" . implode("', '", $mechanisms) . "' mechanisms and the '" . implode("', '", $modifiers) . "' modifiers is {$count} (it should not exceed 10)",
                Issue::LEVEL_WARNING
            ),
        ];
    }

    /**
     * @return \SPFLib\Semantic\Issue[]
     *
     * @see https://tools.ietf.org/html/rfc7208#section-5.1
     */
    protected function checkAllIsLastMechanism(Record $record): array
    {
        $mechanisms = $record->getMechanisms();
        $count = count($mechanisms);
        for ($i = 0; $i < $count - 1; $i++) {
            if ($mechanisms[$i] instanceof Mechanism\AllMechanism) {
                return [
                    new Issue(
                        $record,
                        Issue::CODE_ALL_NOT_LAST_MECHANISM,
                        "'" . Mechanism\AllMechanism::HANDLE . "' should be the last mechanism (any other mechanism will be ignored)",
                        Issue::LEVEL_WARNING
                    ),
                ];
            }
        }

        return [];
    }

    /**
     * @return \SPFLib\Semantic\Issue[]
     *
     * @see https://tools.ietf.org/html/rfc7208#section-5.1
     */
    protected function checkAllAndRedirect(Record $record): array
    {
        $all = array_filter(
            $record->getMechanisms(),
            static function (Mechanism $mechanism): bool {
                return $mechanism instanceof Mechanism\AllMechanism;
            }
        );
        $redirect = array_filter(
            $record->getModifiers(),
            static function (Modifier $modifier): bool {
                return $modifier instanceof Modifier\RedirectModifier;
            }
        );
        if ($all !== [] && $redirect !== []) {
            return [
                new Issue(
                    $record,
                    Issue::CODE_ALL_AND_REDIRECT,
                    "The '" . Modifier\RedirectModifier::HANDLE . "' modifier will be ignored since there's a '" . Mechanism\AllMechanism::HANDLE . "' mechanism",
                    Issue::LEVEL_WARNING
                ),
            ];
        }

        return [];
    }

    /**
     * @return \SPFLib\Semantic\Issue[]
     *
     * @see https://tools.ietf.org/html/rfc7208#section-5.5
     */
    protected function checkNoPtr(Record $record): array
    {
        foreach ($record->getMechanisms() as $mechanism) {
            if ($mechanism instanceof Mechanism\PtrMechanism) {
                return [
                    new Issue(
                        $record,
                        Issue::CODE_SHOULD_AVOID_PTR,
                        "The '" . Mechanism\PtrMechanism::HANDLE . "' mechanism shouldn't be used because it's slow, resource intensive, and not very reliable",
                        Issue::LEVEL_NOTICE
                    ),
                ];
            }
        }

        return [];
    }

    /**
     * @return \SPFLib\Semantic\Issue[]
     *
     * @see https://tools.ietf.org/html/rfc7208#section-6
     */
    protected function checkModifiersPosition(Record $record): array
    {
        $mechanismFound = false;
        $misplacedModifiers = [];
        foreach (array_reverse($record->getTerms()) as $term) {
            if ($term instanceof Mechanism) {
                $mechanismFound = true;
            } elseif ($mechanismFound && $term instanceof Modifier) {
                switch ($term->getName()) {
                    case Modifier\RedirectModifier::HANDLE:
                    case Modifier\ExpModifier::HANDLE:
                        $misplacedModifiers[] = (string) $term;
                        break;
                }
            }
        }
        if ($misplacedModifiers !== []) {
            return [
                new Issue(
                    $record,
                    Issue::CODE_MODIFIER_NOT_AFTER_MECHANISMS,
                    "The modifiers ('" . implode("', '", array_reverse($misplacedModifiers)) . "') should be after all the mechanisms",
                    Issue::LEVEL_NOTICE
                ),
            ];
        }

        return [];
    }

    /**
     * @return \SPFLib\Semantic\Issue[]
     *
     * @see https://tools.ietf.org/html/rfc7208#section-6
     */
    protected function checkModifiersUniqueness(Record $record): array
    {
        $counters = [
            Modifier\RedirectModifier::HANDLE => 0,
            Modifier\ExpModifier::HANDLE => 0,
        ];
        foreach ($record->getModifiers() as $modifier) {
            $name = $modifier->getName();
            if (!isset($counters[$name])) {
                continue;
            }
            $counters[$name]++;
        }
        $result = [];
        foreach ($counters as $name => $count) {
            if ($count > 1) {
                $result[] = new Issue(
                    $record,
                    Issue::CODE_DUPLICATED_MODIFIER,
                    "The '{$name}' modifier is present more than once ({$count} times)",
                    Issue::LEVEL_FATAL
                );
            }
        }

        return $result;
    }

    protected function checkUnknownModifiers(Record $record): array
    {
        $result = [];
        foreach ($record->getModifiers() as $modifier) {
            if ($modifier instanceof Modifier\UnknownModifier) {
                $result[] = new Issue(
                    $record,
                    Issue::UNKNOWN_MODIFIER,
                    "The '{$modifier}' modifier is unknown",
                    Issue::LEVEL_NOTICE
                );
            }
        }

        return $result;
    }
}
