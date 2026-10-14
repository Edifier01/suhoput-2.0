<?php
declare(strict_types=1);
namespace Suhoput\Core\Domain;

final class Availability
{
    /** Quantities are normalized integral units; raw API responses belong to the adapter. */
    public static function calculate(string $warehouse, array $snapshots, array $holds): int
    {
        $row = $snapshots[$warehouse] ?? null;
        if ($warehouse === '' || !is_array($row) || ($row['complete'] ?? null) !== true) {
            throw new \InvalidArgumentException('Selected warehouse snapshot is unknown.');
        }
        if (!is_int($row['physical'] ?? null) || !is_int($row['reserved'] ?? null) || $row['reserved'] < 0) {
            throw new \InvalidArgumentException('Invalid stock quantity.');
        }
        $available = max(0, $row['physical'] - $row['reserved']);
        foreach ($holds as $hold) {
            if (!is_int($hold['quantity'] ?? null) || $hold['quantity'] < 0 || !is_bool($hold['reflected'] ?? null)) {
                throw new \InvalidArgumentException('Invalid local hold.');
            }
            if (!$hold['reflected']) { $available = max(0, $available - $hold['quantity']); }
        }
        return $available;
    }
}
