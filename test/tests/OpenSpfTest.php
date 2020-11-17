<?php

declare(strict_types=1);

use SPFLib\Check\Environment;
use SPFLib\Checker;
use SPFLib\Test\OpenSPF\TestSuite\CaseData;
use SPFLib\Test\OpenSPF\TestSuite\CaseList;
use SPFLib\Test\OpenSPF\TestSuite\CasesGenerator;
use SPFLib\Test\TestCase;

class OpenSpfTest extends TestCase
{
    /**
     * @var string
     */
    protected const EXPLANATION_DEFAULT_MAGIC_CONSTANT = 'DEFAULT';

    public function provideCases(): array
    {
        $result = [];
        $generator = new CasesGenerator();
        foreach ($generator->generateTestCases(SPFLIB_TESTDIR . '/assets/openspf/test-suite') as $caseList) {
            foreach ($caseList->getCasesData() as $caseData) {
                $result[] = [$caseList, $caseData];
            }
        }

        return $result;
    }

    /**
     * @dataProvider provideCases
     */
    public function testCase(CaseList $caseList, CaseData $caseData): void
    {
        $message = $caseList->getDescription() . '/' . $caseData->getID() . ' ' . ($caseData->getDescription() ?: $caseData->getComment());
        $checker = new Checker($caseList->getDNSResolver());
        $environment = new Environment($caseData->getHost(), $caseData->getHelo(), $caseData->getMailFrom());
        $result = $checker->check($environment);
        $this->assertContains($result->getCode(), $caseData->getAllowedResults(), $message . ' - valid values: ' . implode('|', $caseData->getAllowedResults()));
        switch ($caseData->getExplanation()) {
            case static::EXPLANATION_DEFAULT_MAGIC_CONSTANT:
                $this->assertSame('', $result->getFailExplanation(), $message);
                break;
            default:
                $this->assertSame(strtolower($caseData->getExplanation()), strtolower($result->getFailExplanation()), $message);
                break;
        }
    }
}
