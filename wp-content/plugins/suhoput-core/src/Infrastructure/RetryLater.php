<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

/** Adapter supplies a parsed Retry-After duration, never raw headers or exception text. */
final class RetryLater extends \RuntimeException
{
    public function __construct(public readonly int $seconds)
    {
        if ($seconds < 1 || $seconds > 86400) { throw new \InvalidArgumentException('Invalid retry delay.'); }
        parent::__construct('Provider requested a delayed retry.');
    }
}
