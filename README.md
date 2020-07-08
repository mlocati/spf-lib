# SPF (Sender Policy Framework) Library

This PHP library allows you to:

- get the SPF record from a domain name
- decode and validate the SPF record
- create the value of a TXT record
- validate an IP address against an SPF record

The implementation is based on [RFC 7208](https://tools.ietf.org/html/rfc7208).

## Usage

### Retrieving the SPF record from a domain name

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
```

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
$record = (new \SPFLib\Decoder())->getRecordFromTXT('v=spf1 all redirect=example1.org redirect=example2.org ptr:foo.bar mx');
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
```


## Do you want to really say thank you?

You can offer me a [monthly coffee](https://github.com/sponsors/mlocati) or a [one-time coffee](https://paypal.me/mlocati) :wink:
