<?php
use Suhoput\Core\Infrastructure\Schema;
if (wp_get_environment_type() !== 'local') { throw new RuntimeException('Local tests only.'); }
global $wpdb;
$originalPrefix = $wpdb->prefix;
$originalOptions = $wpdb->options;
$fixturePrefix = 'fixture_' . bin2hex(random_bytes(6)) . '_';
$fixtureOptions = $fixturePrefix . 'options';
$tables = array_map(static fn(string $name): string => $fixturePrefix . 'suhoput_' . $name,
    ['links', 'accounts', 'operations', 'inbox', 'notifications', 'holds', 'order_access', 'guest_rates', 'guest_slots']);
$resetCache = static function (): void {
    foreach (['suhoput_schema_version', 'alloptions', 'notoptions', 'wp_user_roles'] as $key) {
        wp_cache_delete($key, 'options');
    }
};
$failAlter = static function(string $sql) use ($fixturePrefix): string {
    if (str_contains($sql, $fixturePrefix . 'suhoput_operations') && str_contains($sql, 'ADD UNIQUE KEY') && str_contains($sql, 'provider_key')) {
        return 'SELECT * FROM ' . $fixturePrefix . 'intentionally_missing_table';
    }
    return $sql;
};
$assert = static function(bool $ok, string $name): void { if (!$ok) { throw new RuntimeException('FAIL: ' . $name); } };
$previousErrors = $wpdb->suppress_errors(true);
try {
    $assert($wpdb->query("CREATE TABLE {$fixtureOptions} LIKE {$originalOptions}") !== false, 'Isolated options table');
    $wpdb->prefix = $fixturePrefix;
    $wpdb->options = $fixtureOptions;
    $resetCache();
    Schema::migrate();
    $operations = $fixturePrefix . 'suhoput_operations';
    $assert($wpdb->query("ALTER TABLE {$operations} MODIFY operation_id char(36) NOT NULL, MODIFY idempotency_key varchar(64) DEFAULT NULL") !== false, 'Prepare old v2 key types');
    $legacyId = wp_generate_uuid4();
    $assert($wpdb->insert($operations, ['operation_id'=>$legacyId, 'order_id'=>1, 'composition_version'=>1, 'provider'=>'fixture', 'action'=>'probe', 'idempotency_key'=>'Legacy-Key', 'request_body'=>'{}', 'request_hash'=>hash('sha256','{}'), 'created_at'=>'2026-10-08 00:00:00', 'updated_at'=>'2026-10-08 00:00:00']) === 1, 'Legacy operation persisted');
    update_option('suhoput_schema_version', 2, false);
    Schema::migrate();
    $assert($wpdb->get_var($wpdb->prepare("SELECT idempotency_key FROM {$operations} WHERE operation_id=%s", $legacyId)) === 'Legacy-Key', 'Type upgrade preserves existing intention');
    $assert($wpdb->query("ALTER TABLE {$fixturePrefix}suhoput_operations DROP INDEX provider_key") !== false, 'Prepare missing unique index');
    update_option('suhoput_schema_version', 1, false);
    add_filter('query', $failAlter);
    $failed = false;
    try { Schema::migrate(); } catch (RuntimeException $error) { $failed = true; }
    remove_filter('query', $failAlter);
    $assert($failed, 'Failed ALTER must fail migration');
    $assert((int)get_option('suhoput_schema_version') === 1, 'Failed migration must retain prior version');
    Schema::migrate();
    $assert((int)get_option('suhoput_schema_version') === Schema::VERSION, 'Successful retry publishes version');
    $indexes = $wpdb->get_results("SHOW INDEX FROM {$fixturePrefix}suhoput_operations WHERE Key_name = 'provider_key'");
    $assert(count($indexes) === 2 && (int)$indexes[0]->Non_unique === 0, 'Retry restores database uniqueness');
    echo "PASS: failed ALTER rejected, prior version retained, retry restores unique index\n";
} finally {
    remove_filter('query', $failAlter);
    $wpdb->prefix = $originalPrefix;
    $wpdb->options = $originalOptions;
    $resetCache();
    foreach (array_merge($tables, [$fixtureOptions]) as $table) { $wpdb->query("DROP TABLE IF EXISTS {$table}"); }
    $wpdb->suppress_errors($previousErrors);
}
