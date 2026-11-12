<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RiskStudio\Security\Totp;

final class TotpTest extends TestCase
{
    /** RFC 6238 appendix B, SHA-1 secret "12345678901234567890", last 6 digits. */
    private const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    public function testRfc6238Vectors(): void
    {
        foreach ([59 => '287082', 1111111109 => '081804', 1111111111 => '050471', 1234567890 => '005924', 2000000000 => '279037'] as $time => $code) {
            self::assertSame($code, Totp::code(self::RFC_SECRET, intdiv($time, 30)), "t={$time}");
        }
    }

    public function testVerifyAcceptsOneStepOfDriftAndReturnsTheStep(): void
    {
        $now = 1_700_000_000;
        $step = intdiv($now, 30);

        self::assertSame($step, Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $step), null, $now));
        self::assertSame($step - 1, Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $step - 1), null, $now));
        self::assertNull(Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $step - 3), null, $now));
        self::assertSame($step, Totp::verify(self::RFC_SECRET, substr_replace(Totp::code(self::RFC_SECRET, $step), ' ', 3, 0), null, $now));
    }

    public function testReplayIsRefused(): void
    {
        $now = 1_700_000_000;
        $step = intdiv($now, 30);
        $code = Totp::code(self::RFC_SECRET, $step);

        self::assertNull(Totp::verify(self::RFC_SECRET, $code, $step, $now), 'same step twice');
        self::assertNull(Totp::verify(self::RFC_SECRET, 'abcdef', null, $now));
    }

    public function testBase32RoundTripAndSecretSize(): void
    {
        $bytes = random_bytes(20);
        self::assertSame($bytes, Totp::base32Decode(Totp::base32Encode($bytes)));
        self::assertSame('12345678901234567890', Totp::base32Decode(self::RFC_SECRET));
        self::assertMatchesRegularExpression('/^[A-Z2-7]{32}$/', Totp::generateSecret());
    }
}
