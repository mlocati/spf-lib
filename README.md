[![Tests](https://github.com/mlocati/spf-lib/workflows/Tests/badge.svg)](https://github.com/mlocati/spf-lib/actions?query=workflow%3A%22Tests%22)

# SPF (Sender Policy Framework) Library

This PHP library allows you to:

- get the SPF record from a domain name
- decode and validate the SPF record
- create the value of a TXT record

The implementation is based on [RFC 7208](https://tools.ietf.org/html/rfc7208).

## Installation

You can install this library with Composer:

```sh
composer require mlocati/spf-lib
```

## Usage

### Retrieving the SPF record from a domain name

An SPF record is composed by zero or more terms. Every term can be a mechanism or a modifier.

This library allows you to inspect them:

```php

$decoder = new \SPFLib\Decoder();
try {
    $record = $decoder->getRecordFromDomain('example.com');
} catch (\SPFLib\Exception $x) {
    // Problems retrieving the SPF record from example.com,
    // or problems decoding it
    return;
}
if ($record === null) {
    // SPF record not found for example.com
    return;
}
// List all terms (that is, mechanisms and modifiers)
foreach ($record->getTerms() as $term) {
    // do your stuff
}
// List all mechanisms
foreach ($record->getMechanisms() as $mechanism) {
    // do your stuff
}
// List all modifiers
foreach ($record->getModifiers() as $modifiers) {
    // do your stuff
}
```

Please note that:

- all [mechanisms](https://github.com/mlocati/spf-lib/tree/master/src/Term/Mechanism) extend the [`SPFLib\Term\Mechanism`](https://github.com/mlocati/spf-lib/blob/master/src/Term/Mechanism.php) abstract class.
- all [modifiers](https://github.com/mlocati/spf-lib/tree/master/src/Term/Modifier) extend the [`SPFLib\Term\Modifier`](https://github.com/mlocati/spf-lib/blob/master/src/Term/Modifier.php) abstract class.
- both mechanisms and modifiers implement the [`SPFLib\Term`](https://github.com/mlocati/spf-lib/blob/master/src/Term.php) interface.

### Decoding the SPF record from the value of a TXT DNS record

```php
$txtRecord = 'v=spf1 mx a -all';
$decoder = new \SPFLib\Decoder();
try {
    $record = $decoder->getRecordFromTXT($txtRecord);
} catch (\SPFLib\Exception $x) {
    // Problems decoding $txtRecord (it's malformed).
    return;
}
if ($record === null) {
    // $txtRecord is not an SPF record
    return;
}
```

### Creating the value of an SPF record

```php
use SPFLib\Term\Mechanism;

$record = new \SPFLib\Record('example.org');
$record
    ->addTerm(new Mechanism\MxMechanism(Mechanism::QUALIFIER_PASS))
    ->addTerm(new Mechanism\IncludeMechanism(Mechanism::QUALIFIER_PASS, 'example.com'))
    ->addTerm(new Mechanism\AllMechanism(Mechanism::QUALIFIER_FAIL))
;
echo (string) $record;
```

Output:

```
v=spf1 mx include:example.com -all
```

### Checking problems with an SPF record

```php
$record = (new \SPFLib\Decoder())->getRecordFromTXT('v=spf1 all redirect=example1.org redirect=example2.org ptr:foo.bar mx include=example3.org');
$issues = (new \SPFLib\SemanticValidator())->validate($record);
foreach ($issues as $issue) {
    echo (string) $issue, "\n";
}
```

Output:

```
[warning] 'all' should be the last mechanism (any other mechanism will be ignored)
[warning] The 'redirect' modifier will be ignored since there's a 'all' mechanism
[notice] The 'ptr' mechanism shouldn't be used because it's slow, resource intensive, and not very reliable
[notice] The modifiers ('redirect=example1.org', 'redirect=example2.org') should be after all the mechanisms
[fatal] The 'redirect' modifier is present more than once (2 times)
[notice] The 'include=example3.org' modifier is unknown
```

Please note that every item in the array returned by the `validate` method is an instance of the [`SPFLib\Semantic\Issue`](https://github.com/mlocati/spf-lib/blob/master/src/Semantic/Issue.php) class.


## Do you want to really say thank you?

You can offer me a [monthly coffee](https://github.com/sponsors/mlocati) or a [one-time coffee](https://paypal.me/mlocati) :wink:
