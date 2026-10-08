<?php
declare(strict_types=1);
namespace Suhoput\Core\Domain;

final readonly class OperationResult
{
    private function __construct(public string $status, public array $evidence) {}

    public static function confirmed(array $evidence): self
    {
        if ($evidence === []) { throw new \InvalidArgumentException('Confirmation needs evidence.'); }
        return new self('confirmed', $evidence);
    }

    public static function refused(string $reason): self
    {
        if ($reason === '') { throw new \InvalidArgumentException('Refusal needs a reason.'); }
        return new self('refused', ['reason' => $reason]);
    }

    public static function unknown(): self { return new self('unknown', []); }
    public function allowsDependentAction(): bool { return $this->status === 'confirmed'; }
}
