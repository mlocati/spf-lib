<?php

declare(strict_types=1);

namespace SPFLib\Test;

use PHPUnit\Framework\TestCase as PHPUnitTestCase;

abstract class TestCase extends PHPUnitTestCase
{
    /**
     * {@inheritdoc}
     *
     * @see \PHPUnit\Framework\TestCase::assertMatchesRegularExpression()
     * @see \PHPUnit\Framework\TestCase::assertRegExp()
     */
    public static function assertRegularExpression(string $pattern, string $string, string $message = ''): void
    {
        if (method_exists(__CLASS__, 'assertMatchesRegularExpression')) {
            self::assertMatchesRegularExpression($pattern, $string, $message);
        } else {
            self::assertRegExp($pattern, $string, $message);
        }
    }
}
