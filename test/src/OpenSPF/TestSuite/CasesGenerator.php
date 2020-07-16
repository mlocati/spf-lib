<?php

declare(strict_types=1);

namespace SPFLib\Test\OpenSPF\TestSuite;

use Generator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RegexIterator;
use RuntimeException;
use SPFLib\DNS\Resolver;
use SPFLib\Exception\DNSResolutionException;
use SPFLib\Test\FakeDnsResoler;
use SplFileInfo;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

class CasesGenerator
{
    /**
     * @return \Generator|\SPFLib\Test\OpenSPF\TestSuite\CaseList
     */
    public function generateTestCases(string $directory): Generator
    {
        foreach ($this->readYamlTestFiles($directory) as $dataKey => $data) {
            $dnsResolver = $this->buildDNSResolver($data);
            unset($data['zonedata']);
            $cases = new CaseList($dataKey, $data['description'], $data['comment'] ?? '', $dnsResolver);
            unset($data['description'],$data['comment']);
            foreach ($data['tests'] as $caseID => $caseData) {
                $cases->addCase($this->parseCaseData($caseID, $caseData));
            }
            unset($data['tests']);
            if ($data !== []) {
                throw new RuntimeException("Unrecognized OpenSPF data keys:\n- " . implode("\n- ", array_keys($data)));
            }
            yield $cases;
        }
    }

    protected function readYamlTestFiles(string $directory): Generator
    {
        foreach ($this->listYamlTestFiles($directory) as $dataKey => $fullPath) {
            $partIndex = 0;
            $fd = fopen($fullPath, 'r');
            try {
                $lines = [];
                while (($line = fgets($fd)) !== false) {
                    $line = rtrim($line, "\r\n");
                    if (strpos($line, '---') === 0) {
                        $data = $lines === [] ? null : Yaml::parse(implode("\n", $lines));
                        if ($data !== null && $data !== []) {
                            yield "{$dataKey}/{$partIndex}" => $data;
                            $partIndex++;
                        }
                        $lines = [];
                    } else {
                        $lines[] = $line;
                    }
                }
                $data = $lines === [] ? null : Yaml::parse(implode("\n", $lines));
                if ($data !== null && $data !== []) {
                    yield "{$dataKey}/{$partIndex}" => $data;
                }
            } catch (ParseException $x) {
                throw new RuntimeException("Failed to decode file {$fullPath}: {$x->getMessage()}", $x->getCode(), $x);
            } finally {
                fclose($fd);
            }
        }
    }

    protected function listYamlTestFiles(string $directory): Generator
    {
        $directory = rtrim(str_replace('/', DIRECTORY_SEPARATOR, $directory), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $directoryIterator = new RecursiveDirectoryIterator($directory);
        $recursiveIterator = new RecursiveIteratorIterator($directoryIterator);
        $filterIterator = new RegexIterator($recursiveIterator, '/.\.ya?ml$/i');
        foreach ($filterIterator as $item) {
            if ($item instanceof SplFileInfo && $item->isFile()) {
                $pathName = str_replace('/', DIRECTORY_SEPARATOR, $item->getPathname());
                $key = substr($pathName, strlen($directory));
                $key = str_replace(DIRECTORY_SEPARATOR, '/', $key);
                $key = preg_replace('/\.\w+$/', '', $key);
                yield $key => $pathName;
            }
        }
    }

    protected function buildDNSResolver(array $data): Resolver
    {
        $txtRecords = [];
        $forwardLookups = [];
        $mxRecords = [];
        $ptrRecords = [];
        $reverseLookups = [];
        foreach ($data['zonedata'] as $dnsName => $maps) {
            $configuredVarNames = [];
            $spfRecords = [];
            $noTXTRecords = false;
            foreach ($maps as $mapIndex => $dnsRecords) {
                if (!is_numeric($mapIndex)) {
                    throw new RuntimeException("Unexpected zonedata key ({$mapIndex} not numeric)");
                }
                if ($dnsRecords === 'TIMEOUT') {
                    foreach (array_diff(['txtRecords', 'forwardLookups', 'mxRecords', 'ptrRecords'], $configuredVarNames) as $varName) {
                        ${$varName}[$dnsName] = new DNSResolutionException($dnsName, 'Fake timeout');
                    }
                } else {
                    foreach ($dnsRecords as $type => $value) {
                        switch (strtoupper($type)) {
                            case 'A':
                            case 'AAAA':
                                $varName = 'forwardLookups';
                                break;
                            case 'SPF':
                                $varName = 'spfRecords';
                                break;
                            case 'TXT':
                                $varName = 'txtRecords';
                                break;
                            case 'MX':
                                $varName = 'mxRecords';
                                if (!is_array($value) || count($value) !== 2 || !is_int($value[0]) || !is_string($value[1])) {
                                    throw new RuntimeException("Unrecognized zonedata record for type ({$type})");
                                }
                                $value = $value[1];
                                break;
                            case 'PTR':
                                $varName = 'ptrRecords';
                                break;
                            default:
                                throw new RuntimeException("Unexpected zonedata record type ({$type})");
                        }
                        if ($type === 'TXT' && $value === 'NONE') {
                            $noTXTRecords = true;
                        } else {
                            $configuredVarNames[] = $varName;
                            if (is_array($value)) {
                                $value = implode('', $value);
                            }
                            if (!isset(${$varName}[$dnsName])) {
                                ${$varName}[$dnsName] = [];
                            }
                            ${$varName}[$dnsName][] = $value;
                        }
                    }
                }
            }

            if ($noTXTRecords === false) {
                foreach ($spfRecords as $key => $values) {
                    if (!isset($txtRecords[$key])) {
                        $txtRecords[$key] = $values;
                    }
                }
            }
        }

        return FakeDnsResoler::create()
            ->setFakeTXTRecords($txtRecords)
            ->setFakeForwardLookups($forwardLookups)
            ->setFakeMXRecords($mxRecords)
            ->setFakePTRRecords($ptrRecords)
            ->setFakeReverseLookups($reverseLookups)
        ;
    }

    protected function parseCaseData(string $caseID, array $data): CaseData
    {
        if (in_array(gettype($data['spec']), ['string', 'double'], true)) {
            $data['spec'] = [(string) $data['spec']];
        }
        foreach ($data['spec'] as $key => $value) {
            if (is_float($value)) {
                $data['spec'][$key] = (string) $value;
            }
        }
        $result = new CaseData(
            $caseID,
            $data['description'] ?? '',
            $data['comment'] ?? '',
            $data['spec'],
            $data['helo'],
            $data['host'],
            $data['mailfrom'],
            (array) $data['result'],
            $data['explanation'] ?? ''
        );
        unset($data['description'], $data['comment'], $data['spec'], $data['helo'], $data['host'], $data['mailfrom'],$data['result'],$data['explanation']);
        if ($data !== []) {
            throw new RuntimeException("Unrecognized OpenSPF test data keys:\n- " . implode("\n- ", array_keys($data)));
        }

        return $result;
    }
}
