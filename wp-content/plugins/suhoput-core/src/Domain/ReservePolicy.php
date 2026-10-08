<?php
declare(strict_types=1);
namespace Suhoput\Core\Domain;

/** Pure decision model. It never performs external actions or updates an order. */
final class ReservePolicy
{
    private const PAYMENT_STATUSES = ['none', 'pending', 'canceled', 'succeeded', 'unknown', 'waiting_for_capture'];

    public static function deadline(string $context, int $firstSavedAt): int
    {
        $seconds = match ($context) {
            'retail' => 3600,
            'wholesale' => 86400,
            default => throw new \InvalidArgumentException('Invalid buyer context.'),
        };
        if ($firstSavedAt < 0 || $firstSavedAt > PHP_INT_MAX - $seconds) { throw new \InvalidArgumentException('Invalid time.'); }
        return $firstSavedAt + $seconds;
    }

    public static function retailExpiry(int $now, int $expiresAt, array $attempts, bool $unknownCreation): string
    {
        self::validateAttempts($attempts);
        if (in_array('succeeded', $attempts, true)) { return 'keep_paid'; }
        if ($unknownCreation || array_intersect(['unknown', 'waiting_for_capture'], $attempts)) { return 'wait_manager'; }
        if ($now < $expiresAt) { return 'keep'; }
        return in_array('pending', $attempts, true) ? 'release_watch' : 'release_cancel';
    }

    /** decision must be fetched afresh before a release command; stale data is 'unknown'. */
    public static function wholesaleExpiry(int $now, int $expiresAt, string $decision): string
    {
        return match ($decision) {
            'unknown' => 'wait_manager',
            'confirmed', 'fulfilling' => 'keep',
            'rejected', 'canceled' => 'release_decision',
            'unconfirmed' => $now >= $expiresAt ? 'release_expired' : 'keep',
            default => throw new \InvalidArgumentException('Invalid wholesale decision.'),
        };
    }

    public static function canPay(string $context, int $now, int $expiresAt, string $fullReserve, array $attempts, bool $unknownCreation = false): bool
    {
        self::validateAttempts($attempts);
        return $context === 'retail' && $now < $expiresAt && $fullReserve === 'confirmed' && !$unknownCreation
            && !array_intersect(['pending', 'unknown', 'waiting_for_capture', 'succeeded'], $attempts);
    }

    public static function lateSuccess(string $availability): string
    {
        return match ($availability) {
            'available' => 'reserve_all',
            'insufficient' => 'manager_no_refund',
            'unknown' => 'wait_manager',
            default => throw new \InvalidArgumentException('Invalid availability result.'),
        };
    }

    private static function validateAttempts(array $attempts): void
    {
        foreach ($attempts as $attempt) {
            if (!in_array($attempt, self::PAYMENT_STATUSES, true)) { throw new \InvalidArgumentException('Invalid payment status.'); }
        }
    }
}
