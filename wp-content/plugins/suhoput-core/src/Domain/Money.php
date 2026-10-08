<?php
declare(strict_types=1);
namespace Suhoput\Core\Domain;

final readonly class Money
{
    public function __construct(public int $minor, public string $currency = 'RUB')
    {
        if ($minor < 0 || $currency !== 'RUB') { throw new \InvalidArgumentException('Invalid money.'); }
    }

    public static function fromDecimal(string $amount): self
    {
        if (!preg_match('/\A([0-9]+)(?:\.([0-9]{1,2}))?\z/D', $amount, $match)) {
            throw new \InvalidArgumentException('Invalid decimal amount.');
        }
        $digits = ltrim($match[1] . str_pad($match[2] ?? '', 2, '0'), '0') ?: '0';
        $max = (string) PHP_INT_MAX;
        if (strlen($digits) > strlen($max) || (strlen($digits) === strlen($max) && strcmp($digits, $max) > 0)) {
            throw new \OverflowException('Money overflow.');
        }
        return new self((int) $digits);
    }

    public function add(self $other): self
    {
        if ($other->minor > PHP_INT_MAX - $this->minor) { throw new \OverflowException('Money overflow.'); }
        return new self($this->minor + $other->minor);
    }

    public function decimal(): string
    {
        return intdiv($this->minor, 100) . '.' . str_pad((string) ($this->minor % 100), 2, '0', STR_PAD_LEFT);
    }
}
