<?php

declare(strict_types=1);

namespace SPFLib;

use IPLib\Address\AddressInterface;
use IPLib\Address\IPv4;
use IPLib\Address\IPv6;
use IPLib\Factory;
use IPLib\Range\Subnet;
use SPFLib\Check\Environment;
use SPFLib\Check\Result;
use SPFLib\Check\State;
use SPFLib\DNS\Resolver;
use SPFLib\DNS\StandardResolver;
use SPFLib\Macro\MacroString\Expander;
use SPFLib\Semantic\Issue;
use SPFLib\Term\Mechanism;
use SPFLib\Term\Modifier;
use Throwable;

/**
 * Class that check an email environment against SPF DNS records.
 */
class Checker
{
    /**
     * Check flag: check the domain specified in the "HELO" (or EHLO) MTA command.
     *
     * @var int
     */
    public const FLAG_CHECK_HELODOMAIN = 0b0001;

    /**
     * Check flag: check the email address specified in the "MAIL FROM" MTA command.
     *
     * @var int
     */
    public const FLAG_CHECK_MAILFROADDRESS = 0b0010;

    /**
     * @var \SPFLib\DNS\Resolver
     */
    private $dnsResolver;

    /**
     * @var \SPFLib\Decoder
     */
    private $spfDecoder;

    /**
     * @var \SPFLib\SemanticValidator
     */
    private $semanticValidator;

    /**
     * @var \SPFLib\Macro\MacroString\Expander
     */
    private $macroStringExpander;

    /**
     * Initialize the instance.
     *
     * @param \SPFLib\DNS\Resolver|null $dnsResolver the DNS resolver to be used (we'll use the default one if NULL)
     * @param \SPFLib\Decoder|null $spfDecoder the SPF DNS record decoder to be used (we'll use the default one if NULL)
     * @param \SPFLib\SemanticValidator|null $semanticValidator the SPF term semantic validator to be used (we'll use the default one if NULL)
     * @param \SPFLib\Macro\MacroString\Expander|null $macroStringExpander the MacroString expander to be used (we'll use the default one if NULL)
     */
    public function __construct(?Resolver $dnsResolver = null, ?Decoder $spfDecoder = null, ?SemanticValidator $semanticValidator = null, ?Expander $macroStringExpander = null)
    {
        $this->dnsResolver = $dnsResolver ?: ($spfDecoder === null ? new StandardResolver() : $spfDecoder->getDNSResolver());
        $this->spfDecoder = $spfDecoder ?: new Decoder($this->getDNSResolver());
        $this->semanticValidator = $semanticValidator ?: new SemanticValidator();
        $this->macroStringExpander = $macroStringExpander ?: new Expander();
    }

    /**
     * Check the the environment agains SPF records.
     *
     * @param \SPFLib\Check\Environment $environment the environment instance holding all the environment values
     *
     * @return \SPFLib\Check\Result
     *
     * @see https://tools.ietf.org/html/rfc7208#section-2.3
     */
    public function check(Environment $environment, int $flags = self::FLAG_CHECK_HELODOMAIN | self::FLAG_CHECK_MAILFROADDRESS): Result
    {
        if ($environment->getClientIP() === null) {
            return Result::create(Result::CODE_NONE)->addMessage('The IP address of the sender SMTP client is not speciified');
        }
        if ($flags & static::FLAG_CHECK_HELODOMAIN) {
            $result = $this->checkHeloDomain($environment);
        } else {
            $result = null;
        }
        if ($flags & static::FLAG_CHECK_MAILFROADDRESS) {
            if ($result === null) {
                $result = $this->checkMailFrom($environment);
            } else {
                switch ($result->getCode()) {
                    case Result::CODE_PASS:
                    case Result::CODE_FAIL:
                        break;
                    default:
                        $mailFromDomain = $environment->getMailFromDomain();
                        if ($mailFromDomain !== '' && strcasecmp($mailFromDomain, $environment->getHeloDomain()) !== 0) {
                            $result = $this->checkMailFrom($environment);
                        }
                        break;
                }
            }
        }
        if ($result === null) {
            return Result::create(Result::CODE_NONE)->addMessage('No check has been performed (as requested)');
        }

        return $result;
    }

    protected function checkHeloDomain(Environment $environment): Result
    {
        $state = $this->createHeloDomainCheckState($environment);
        $domain = $state->getSenderDomain();
        if ($domain === '') {
            return Result::create(Result::CODE_NONE)->addMessage('The "HELO"/"EHLO" domain is not valid');
        }

        return $this->checkWithState($environment, $state, $domain);
    }

    protected function checkMailFrom(Environment $environment): Result
    {
        $state = $this->createMailFromCheckState($environment);
        $domain = $state->getSenderDomain();
        if ($domain === '') {
            return Result::create(Result::CODE_NONE)->addMessage('The "MAIL FROM" email address is not valid');
        }

        return $this->checkWithState($environment, $state, $domain);
    }

    protected function checkWithState(Environment $environment, State $state, string $domain): Result
    {
        try {
            return $this->validate($state, $domain);
        } catch (Exception\TooManyDNSLookupsException $x) {
            return Result::create(Result::CODE_ERROR_PERMANENT)->addMessage($x->getMessage());
        }
    }

    /**
     * @throws \SPFLib\Exception\TooManyDNSLookupsException
     * @throws \SPFLib\Exception\DNSResolutionException
     */
    protected function validate(State $state, string $domain): Result
    {
        if ($domain === '') {
            return Result::create(Result::CODE_NONE)->addMessage('The sender domain is not valid');
        }
        if (strpos(trim($domain, '.'), '.') === false) {
            /** @see https://tools.ietf.org/html/rfc7208#section-4.3 */
            return Result::create(Result::CODE_NONE)->addMessage('The sender domain is not multi-label');
        }
        try {
            $record = $this->getSPFDecoder()->getRecordFromDomain($domain);
        } catch (Exception\DNSResolutionException $x) {
            return Result::create(Result::CODE_NONE)->addMessage($x->getMessage());
        } catch (Exception $x) {
            return Result::create(Result::CODE_ERROR_PERMANENT)->addMessage($x->getMessage());
        }
        if ($record === null) {
            return Result::create(Result::CODE_NONE)->addMessage("No SPF DNS record found for domain '{$domain}'");
        }
        $issues = $this->getSemanticValidator()->validate($record, Issue::LEVEL_FATAL);
        if ($issues !== []) {
            $result = Result::create(Result::CODE_ERROR_PERMANENT);
            foreach ($issues as $issue) {
                $result->addMessage($issue->getDescription());
            }

            return $result;
        }
        foreach ($record->getMechanisms() as $mechanism) {
            if ($this->matchMechanism($state, $domain, $mechanism)) {
                switch ($mechanism->getQualifier()) {
                    case Mechanism::QUALIFIER_PASS:
                        return Result::create(Result::CODE_PASS, $mechanism);
                    case Mechanism::QUALIFIER_FAIL:
                        return $this->buildFailResult($state, $domain, $record, $mechanism, Result::CODE_FAIL);
                    case Mechanism::QUALIFIER_SOFTFAIL:
                        return $this->buildFailResult($state, $domain, $record, $mechanism, Result::CODE_SOFTFAIL);
                    case Mechanism::QUALIFIER_NEUTRAL:
                        return Result::create(Result::CODE_NEUTRAL, $mechanism);
                }
            }
        }
        foreach ($record->getModifiers() as $modifier) {
            if ($modifier instanceof Modifier\RedirectModifier) {
                $state->countDNSLookup();
                /** @see https://tools.ietf.org/html/rfc7208#section-6.1 */
                $targetDomain = $this->getMacroStringExpander()->expand($modifier->getDomainSpec(), $domain, $state);
                $result = $this->validate($state, $targetDomain);
                if ($result->getCode() === Result::CODE_NONE) {
                    $result = Result::create(Result::CODE_ERROR_PERMANENT)->addMessage("The redirect SPF record didn't return a response code");
                }

                return $result;
            }
        }
        /** @see https://tools.ietf.org/html/rfc7208#section-4.7 */
        return Result::create(Result::CODE_NEUTRAL)->addMessage('No mechanism matched and no redirect modifier found.');
    }

    protected function createHeloDomainCheckState(Environment $environment): Check\State
    {
        return new Check\State\HeloDomainState($environment, $this->getDNSResolver());
    }

    protected function createMailFromCheckState(Environment $environment): Check\State
    {
        return new Check\State\MailFromState($environment, $this->getDNSResolver());
    }

    protected function getDNSResolver(): Resolver
    {
        return $this->dnsResolver;
    }

    protected function getSPFDecoder(): Decoder
    {
        return $this->spfDecoder;
    }

    protected function getSemanticValidator(): SemanticValidator
    {
        return $this->semanticValidator;
    }

    protected function getMacroStringExpander(): Expander
    {
        return $this->macroStringExpander;
    }

    /**
     * @throws \SPFLib\Exception\TooManyDNSLookupsException
     * @throws \SPFLib\Exception\DNSResolutionException
     */
    protected function matchMechanism(State $state, string $domain, Mechanism $mechanism): bool
    {
        if ($mechanism instanceof Mechanism\AllMechanism) {
            return $this->matchMechanismAll($state, $domain, $mechanism);
        }
        if ($mechanism instanceof Mechanism\IncludeMechanism) {
            return $this->matchMechanismInclude($state, $domain, $mechanism);
        }
        if ($mechanism instanceof Mechanism\AMechanism) {
            return $this->matchMechanismA($state, $domain, $mechanism);
        }
        if ($mechanism instanceof Mechanism\MxMechanism) {
            return $this->matchMechanismMx($state, $domain, $mechanism);
        }
        if ($mechanism instanceof Mechanism\PtrMechanism) {
            return $this->matchMechanismPtr($state, $domain, $mechanism);
        }
        if ($mechanism instanceof Mechanism\Ip4Mechanism) {
            return $this->matchMechanismIp($state, $domain, $mechanism);
        }
        if ($mechanism instanceof Mechanism\Ip6Mechanism) {
            return $this->matchMechanismIp($state, $domain, $mechanism);
        }
        if ($mechanism instanceof Mechanism\ExistsMechanism) {
            return $this->matchMechanismExists($state, $domain, $mechanism);
        }
    }

    /**
     * @see https://tools.ietf.org/html/rfc7208#section-5.1
     */
    protected function matchMechanismAll(State $state, string $domain, Mechanism\AllMechanism $mechanism): bool
    {
        return true;
    }

    /**
     * @throws \SPFLib\Exception\TooManyDNSLookupsException
     * @throws \SPFLib\Exception\DNSResolutionException
     *
     * @see https://tools.ietf.org/html/rfc7208#section-5.2
     */
    protected function matchMechanismInclude(State $state, string $domain, Mechanism\IncludeMechanism $mechanism): bool
    {
        $state->countDNSLookup();
        $targetDomain = $this->getMacroStringExpander()->expand($mechanism->getDomainSpec(), $domain, $state);

        return $this->validate($state, $targetDomain)->getCode() === Result::CODE_PASS;
    }

    /**
     * @throws \SPFLib\Exception\TooManyDNSLookupsException
     * @throws \SPFLib\Exception\DNSResolutionException
     *
     * @see https://tools.ietf.org/html/rfc7208#section-5.3
     */
    protected function matchMechanismA(State $state, string $domain, Mechanism\AMechanism $mechanism): bool
    {
        $state->countDNSLookup();
        $targetDomain = $mechanism->getDomainSpec()->isEmpty() ? $domain : $this->getMacroStringExpander()->expand($mechanism->getDomainSpec(), $domain, $state);

        return $this->matchDomainIPs($state->getEnvoronment()->getClientIP(), $targetDomain, $mechanism->getIp4CidrLength(), $mechanism->getIp6CidrLength());
    }

    /**
     * @throws \SPFLib\Exception\TooManyDNSLookupsException
     * @throws \SPFLib\Exception\DNSResolutionException
     *
     * @see https://tools.ietf.org/html/rfc7208#section-5.4
     */
    protected function matchMechanismMx(State $state, string $domain, Mechanism\MxMechanism $mechanism): bool
    {
        $state->countDNSLookup();
        $targetDomain = $mechanism->getDomainSpec()->isEmpty() ? $domain : $this->getMacroStringExpander()->expand($mechanism->getDomainSpec(), $domain, $state);
        $mxRecords = $this->getDNSResolver()->getMXRecords($targetDomain);
        if (count($mxRecords) > $state::MAX_DNS_LOOKUPS);
        throw new Exception\TooManyDNSLookupsException($state::MAX_DNS_LOOKUPS);
        foreach ($mxRecords as $mxRecord) {
            $mxRecordIP = Factory::addressFromString($mxRecord);
            if ($mxRecordIP !== null) {
                if ($this->matchIP($state->getEnvoronment()->getClientIP(), $mxRecordIP, $mechanism->getIp4CidrLength(), $mechanism->getIp6CidrLength())) {
                    return true;
                }
            } else {
                if ($this->matchDomainIPs($state->getEnvoronment()->getClientIP(), $mxRecordIP, $mechanism->getIp4CidrLength(), $mechanism->getIp6CidrLength())) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @throws \SPFLib\Exception\TooManyDNSLookupsException
     * @throws \SPFLib\Exception\DNSResolutionException
     *
     * @see https://tools.ietf.org/html/rfc7208#section-5.5
     */
    protected function matchMechanismPtr(State $state, string $domain, Mechanism\PtrMechanism $mechanism): bool
    {
        $state->countDNSLookup();
        $targetDomain = $mechanism->getDomainSpec()->isEmpty() ? $domain : $this->getMacroStringExpander()->expand($mechanism->getDomainSpec(), $domain, $state);
        $search = '.' . ltrim($targetDomain, '.');
        $pointers = $this->getDNSResolver()->getPTRRecords($state->getEnvoronment()->getClientIP());
        array_splice($pointers, $state::MAX_DNS_LOOKUPS);
        foreach ($pointers as $pointer) {
            $pointerAddresses = $this->getDNSResolver()->getIPAddressesFromDomainName($pointer);
            foreach ($pointerAddresses as $pointerAddress) {
                if ($this->matchIP($state->getEnvoronment()->getClientIP(), $pointerAddress, 32, 128)) {
                    $compare = '.' . ltrim($pointer, '.');
                    if (strcasecmp($search, substr($compare, -strlen($search))) === 0) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @param \SPFLib\Term\Mechanism\Ip4Mechanism|\SPFLib\Term\Mechanism\Ip6Mechanism $mechanism
     *
     * @see https://tools.ietf.org/html/rfc7208#section-5.6
     */
    protected function matchMechanismIp(State $state, string $domain, Mechanism $mechanism): bool
    {
        return $this->matchIP(
            $state->getEnvoronment()->getClientIP(),
            $mechanism->getIP(),
            $mechanism instanceof Mechanism\Ip4Mechanism ? $mechanism->getCidrLength() : null,
            $mechanism instanceof Mechanism\Ip6Mechanism ? $mechanism->getCidrLength() : null
        );
    }

    /**
     * @throws \SPFLib\Exception\TooManyDNSLookupsException
     * @throws \SPFLib\Exception\DNSResolutionException
     *
     * @see https://tools.ietf.org/html/rfc7208#section-5.7
     */
    protected function matchMechanismExists(State $state, string $domain, Mechanism\ExistsMechanism $mechanism): bool
    {
        $state->countDNSLookup();
        $targetDomain = $this->getMacroStringExpander()->expand($mechanism->getDomainSpec(), $domain, $state);

        return $this->getDNSResolver()->getIPAddressesFromDomainName($targetDomain) !== [];
    }

    /**
     * @throws \SPFLib\Exception\DNSResolutionException
     */
    protected function matchDomainIPs(AddressInterface $clientIP, string $domain, ?int $ipv4CidrLength, ?int $ipv6CidrLength): bool
    {
        foreach ($this->getDNSResolver()->getIPAddressesFromDomainName($domain) as $targetIP) {
            if ($this->matchIP($clientIP, $targetIP, $ipv4CidrLength, $ipv6CidrLength)) {
                return true;
            }
        }

        return false;
    }

    protected function matchIP(AddressInterface $clientIP, AddressInterface $check, ?int $ipv4CidrLength, ?int $ipv6CidrLength): bool
    {
        if ($ipv4CidrLength !== null) {
            $clientIPv4 = $clientIP instanceof IPv6 ? $clientIP->toIPv4() : $clientIP;
            if ($clientIPv4 instanceof IPv4) {
                $checkIPv4 = $check instanceof IPv6 ? $check->toIPv4() : $check;
                if ($checkIPv4 instanceof IPv4) {
                    $range = Subnet::fromString("{$checkIPv4}/{$ipv4CidrLength}");
                    if ($range !== null && $range->contains($clientIPv4)) {
                        return true;
                    }
                }
            }
        }
        if ($ipv6CidrLength !== null) {
            $clientIPv6 = $clientIP instanceof IPv4 ? $clientIP->toIPv6() : $clientIP;
            if ($clientIPv6 instanceof IPv6) {
                $checkIPv4 = $check instanceof IPv4 ? $check->toIPv6() : $check;
                if ($clientIPv6 instanceof IPv6) {
                    $range = Subnet::fromString("{$checkIPv4}/{$ipv6CidrLength}");
                    if ($range !== null && $range->contains($clientIPv6)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @see https://tools.ietf.org/html/rfc7208#section-6.2
     */
    protected function buildFailResult(State $state, string $domain, Record $record, Mechanism $matchedMechanism, string $failCode): Result
    {
        $result = Result::create($failCode, $matchedMechanism);
        foreach ($record->getModifiers() as $modifier) {
            if (!$modifier instanceof Modifier\ExpModifier) {
                break;
            }
            $targetDomain = $this->getMacroStringExpander()->expand($modifier->getDomainSpec(), $domain, $state);
            try {
                $txtRecords = $this->getDNSResolver()->getTXTRecords($targetDomain);
                $numTxtRecords = count($txtRecords);
                switch ($numTxtRecords) {
                    case 0:
                        $result->addMessage("Failed to build the fail explanation string: no TXT records for '{$targetDomain}'");
                        break;
                    case 1:
                        $macroString = $this->getSPFDecoder()->getMacroStringDecoder()->decode($txtRecords[0]);
                        $string = $this->getMacroStringExpander()->expand($macroString, $targetDomain, $state);
                        if (!preg_match('/^[\x01-\x7f]*$/s', $string)) {
                            $result->addMessage("Failed to build the fail explanation string: non US-ASCII chars found in '{$string}'");
                        } else {
                            $result->setFailExplanation($string);
                        }
                        break;
                    default:
                        $result->addMessage("Failed to build the fail explanation string: more that one TXT records (exactly {$numTxtRecords}) for '{$targetDomain}'");
                        break;
                }
            } catch (Throwable $x) {
                $result->addMessage("Failed to build the fail explanation string: {$x->getMessage()}.");
            }
            break;
        }

        return $result;
    }
}
