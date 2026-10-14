<?php
// Pure rules: synthetic data and controlled UTC timestamps only.
$base = '/var/www/html/wp-content/plugins/suhoput-core/src/Domain/';
foreach (['Money', 'Availability', 'ReservePolicy', 'OperationResult'] as $class) {
    $file = $base . $class . '.php';
    if (is_file($file)) { require_once $file; }
}
if (!class_exists(\Suhoput\Core\Domain\Money::class)) {
    throw new RuntimeException('FAIL: money/availability/reserve contracts not implemented');
}
use Suhoput\Core\Domain\Money;
use Suhoput\Core\Domain\Availability;
use Suhoput\Core\Domain\ReservePolicy;
use Suhoput\Core\Domain\OperationResult;
$count = 0;
$same = static function ($expected, $actual, string $name) use (&$count): void {
    ++$count;
    if ($expected !== $actual) { throw new RuntimeException('FAIL: ' . $name); }
};
$reject = static function (callable $call, string $name) use (&$count): void {
    ++$count;
    try { $call(); } catch (InvalidArgumentException|OverflowException $e) { return; }
    throw new RuntimeException('FAIL: ' . $name);
};
$same(1300000, Money::fromDecimal('13000')->minor, '13000 RUB stays 13000');
$same('13000.10', Money::fromDecimal('13000.1')->decimal(), 'Exact decimal');
$same('0.30', Money::fromDecimal('0.1')->add(Money::fromDecimal('0.2'))->decimal(), 'No float loss');
$reject(fn() => Money::fromDecimal('1.001'), 'No silent rounding');
$reject(fn() => Money::fromDecimal('-1'), 'Negative money');
$reject(fn() => Money::fromDecimal('1e3'), 'Scientific notation rejected');
$reject(fn() => Money::fromDecimal('92233720368547758.08'), 'Money overflow');
$reject(fn() => (new Money(PHP_INT_MAX))->add(new Money(1)), 'Add overflow');
$stock = ['chosen' => ['physical' => 2, 'reserved' => 1, 'complete' => true], 'other' => ['physical' => 100, 'reserved' => 0, 'complete' => true]];
$same(1, Availability::calculate('chosen', $stock, []), 'Other warehouse ignored');
$same(0, Availability::calculate('chosen', $stock, [['quantity' => 1, 'reflected' => false]]), 'Pending hold deducted');
$same(1, Availability::calculate('chosen', $stock, [['quantity' => 1, 'reflected' => true]]), 'External hold not deducted twice');
$reject(fn() => Availability::calculate('missing', $stock, []), 'Missing warehouse is unknown');
$reject(fn() => Availability::calculate('chosen', ['chosen' => ['physical' => 2, 'reserved' => 0, 'complete' => false]], []), 'Incomplete snapshot is unknown');
$same(0, Availability::calculate('chosen', ['chosen' => ['physical' => 0, 'reserved' => 1, 'complete' => true, 'expected' => 100]], []), 'Expected stock excluded');
$t = 1700000000;
$same($t + 3600, ReservePolicy::deadline('retail', $t), 'Retail fixed hour');
$same($t + 86400, ReservePolicy::deadline('wholesale', $t), 'Wholesale fixed day');
$same('keep', ReservePolicy::retailExpiry($t, $t+3600, [], false), 'Before deadline');
$same('release_cancel', ReservePolicy::retailExpiry($t+3600, $t+3600, [], false), 'No payment on deadline');
$same('release_cancel', ReservePolicy::retailExpiry($t+3600, $t+3600, ['canceled'], false), 'All canceled');
$same('release_watch', ReservePolicy::retailExpiry($t+3600, $t+3600, ['canceled', 'pending'], false), 'Confirmed pending release and watch');
$same('wait_manager', ReservePolicy::retailExpiry($t+3600, $t+3600, ['pending','unknown'], false), 'One unknown prevents release');
$same('wait_manager', ReservePolicy::retailExpiry($t+3600, $t+3600, [], true), 'Unknown creation prevents release');
$same('wait_manager', ReservePolicy::retailExpiry($t+3600, $t+3600, ['waiting_for_capture'], false), 'Unexpected capture requires manager');
$same('keep_paid', ReservePolicy::retailExpiry($t+3600, $t+3600, ['succeeded','canceled','unknown'], true), 'Confirmed success has priority');
$same('keep', ReservePolicy::wholesaleExpiry($t+86400, $t+86400, 'confirmed'), 'Wholesale confirmed stays held');
$same('release_expired', ReservePolicy::wholesaleExpiry($t+86400, $t+86400, 'unconfirmed'), 'Fresh decision expiration');
$same('wait_manager', ReservePolicy::wholesaleExpiry($t+86400, $t+86400, 'unknown'), 'Wholesale fresh lookup unavailable');
$same('release_decision', ReservePolicy::wholesaleExpiry($t, $t+86400, 'rejected'), 'Wholesale early rejection');
$same(false, ReservePolicy::canPay('wholesale', $t, $t+86400, 'confirmed', []), 'Wholesale cannot pay');
$same(true, ReservePolicy::canPay('retail', $t, $t+3600, 'confirmed', ['canceled']), 'Single fresh attempt allowed');
foreach (['pending','unknown','waiting_for_capture','succeeded'] as $status) {
    $same(false, ReservePolicy::canPay('retail', $t, $t+3600, 'confirmed', [$status]), 'No overlapping payment: '.$status);
}
$same(false, ReservePolicy::canPay('retail', $t+3600, $t+3600, 'confirmed', []), 'No payment at deadline');
$same(false, ReservePolicy::canPay('retail', $t, $t+3600, 'unknown', []), 'Only confirmed full reserve opens payment');
$same('reserve_all', ReservePolicy::lateSuccess('available'), 'Late payment reserve all');
$same('manager_no_refund', ReservePolicy::lateSuccess('insufficient'), 'Late shortage does not refund');
$same('wait_manager', ReservePolicy::lateSuccess('unknown'), 'API error is not shortage');
$same(false, OperationResult::unknown()->allowsDependentAction(), 'Unknown cannot release dependency');
$same(true, OperationResult::confirmed(['external_id'=>'fixture'])->allowsDependentAction(), 'Confirmed result');
echo "PASS: {$count} contract model checks (simulation)\n";
