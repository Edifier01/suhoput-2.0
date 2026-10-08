<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

final class Schema
{
    public const VERSION = 3;

    public static function migrate(): void
    {
        global $wpdb;
        $lock = 'suhoput_schema_' . substr(hash('sha256', $wpdb->prefix), 0, 24);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 10)', $lock)) !== 1) {
            throw new \RuntimeException('Schema migration is already running.');
        }
        try {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            $p = $wpdb->prefix . 'suhoput_';
            $collate = $wpdb->get_charset_collate();
            // Version 1 accidentally allowed only one variant per whole-order operation.
            $holdsTable = $p . 'holds';
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($holdsTable))) === $holdsTable) {
                $index = $wpdb->get_results("SHOW INDEX FROM {$holdsTable} WHERE Key_name = 'operation_id'");
                if ($index && $wpdb->query("ALTER TABLE {$holdsTable} DROP INDEX operation_id") === false) {
                    throw new \RuntimeException('Could not remove obsolete hold index.');
                }
            }
            $definitions = [
                'links' => "id bigint unsigned NOT NULL AUTO_INCREMENT,
local_type varchar(32) NOT NULL,
local_id bigint unsigned NOT NULL,
provider varchar(64) NOT NULL,
external_type varchar(32) NOT NULL,
external_id varchar(191) COLLATE utf8mb4_bin NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY local_link (local_type,local_id,provider,external_type),
UNIQUE KEY external_link (provider,external_type,external_id)",
                'accounts' => "id bigint unsigned NOT NULL AUTO_INCREMENT,
email_key varchar(100) COLLATE utf8mb4_bin NOT NULL,
user_id bigint unsigned DEFAULT NULL,
buyer_type varchar(16) NOT NULL DEFAULT 'retail',
counterparty_id varchar(191) COLLATE utf8mb4_bin DEFAULT NULL,
access_enabled tinyint unsigned NOT NULL DEFAULT 0,
PRIMARY KEY  (id),
UNIQUE KEY email_key (email_key),
UNIQUE KEY user_id (user_id),
UNIQUE KEY counterparty_id (counterparty_id)",
                'operations' => "id bigint unsigned NOT NULL AUTO_INCREMENT,
operation_id varbinary(36) NOT NULL,
order_id bigint unsigned NOT NULL,
composition_version bigint unsigned NOT NULL,
provider varchar(64) NOT NULL,
action varchar(64) NOT NULL,
idempotency_key varbinary(64) DEFAULT NULL,
request_body longtext NOT NULL,
request_hash char(64) NOT NULL,
state varchar(16) NOT NULL DEFAULT 'queued',
result_body longtext DEFAULT NULL,
attempts int unsigned NOT NULL DEFAULT 0,
next_attempt_at datetime DEFAULT NULL,
lease_until datetime DEFAULT NULL,
created_at datetime NOT NULL,
updated_at datetime NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY operation_id (operation_id),
UNIQUE KEY provider_key (provider,idempotency_key),
KEY runnable (state,next_attempt_at)",
                'inbox' => "id bigint unsigned NOT NULL AUTO_INCREMENT,
provider varchar(64) NOT NULL,
event_key char(64) NOT NULL,
body longtext NOT NULL,
body_hash char(64) NOT NULL,
state varchar(16) NOT NULL DEFAULT 'queued',
received_at datetime NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY provider_event (provider,event_key),
KEY pending (state)",
                'notifications' => "id bigint unsigned NOT NULL AUTO_INCREMENT,
notification_key char(64) NOT NULL,
order_id bigint unsigned NOT NULL,
payload longtext NOT NULL,
state varchar(16) NOT NULL DEFAULT 'queued',
attempts int unsigned NOT NULL DEFAULT 0,
next_attempt_at datetime DEFAULT NULL,
created_at datetime NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY notification_key (notification_key),
KEY runnable (state,next_attempt_at)",
                'holds' => "id bigint unsigned NOT NULL AUTO_INCREMENT,
hold_id varbinary(36) NOT NULL,
order_id bigint unsigned NOT NULL,
composition_version bigint unsigned NOT NULL,
variant_id bigint unsigned NOT NULL,
warehouse_id varchar(191) COLLATE utf8mb4_bin NOT NULL,
quantity bigint unsigned NOT NULL,
state varchar(16) NOT NULL DEFAULT 'pending',
operation_id varbinary(36) NOT NULL,
expires_at datetime NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY hold_id (hold_id),
UNIQUE KEY order_variant (order_id,composition_version,variant_id),
UNIQUE KEY operation_variant (operation_id,variant_id),
KEY variant_state (variant_id,state)",
            ];
            foreach ($definitions as $name => $columns) {
                dbDelta("CREATE TABLE {$p}{$name} (\n{$columns}\n) ENGINE=InnoDB {$collate};");
                self::assertStructure($p . $name, $columns);
            }
            foreach (['administrator', 'shop_manager'] as $roleName) {
                get_role($roleName)?->add_cap('manage_suhoput');
            }
            $previousVersion = (int) get_option('suhoput_schema_version', 0);
            if (!update_option('suhoput_schema_version', self::VERSION, false) && $previousVersion !== self::VERSION) {
                throw new \RuntimeException('Could not persist schema version.');
            }
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }

    /** dbDelta can return normally after SQL errors. Verify its actual postconditions. */
    private static function assertStructure(string $table, string $definition): void
    {
        global $wpdb;
        $status = $wpdb->get_row($wpdb->prepare('SHOW TABLE STATUS LIKE %s', $wpdb->esc_like($table)), ARRAY_A);
        if (!$status || strcasecmp($status['Engine'], 'InnoDB') !== 0) {
            throw new \RuntimeException('Own table migration failed.');
        }
        $columns = [];
        foreach ($wpdb->get_results("SHOW FULL COLUMNS FROM {$table}", ARRAY_A) as $column) { $columns[$column['Field']] = $column; }
        $indexes = [];
        foreach ($wpdb->get_results("SHOW INDEX FROM {$table}", ARRAY_A) as $index) {
            $indexes[$index['Key_name']]['unique'] = (int) $index['Non_unique'] === 0;
            $indexes[$index['Key_name']]['columns'][(int) $index['Seq_in_index']] = $index['Column_name'];
            if ($index['Sub_part'] !== null) { throw new \RuntimeException('Truncated own index is not supported.'); }
        }
        $normalizeType = static fn(string $type): string => strtolower(preg_replace('/(tinyint|smallint|mediumint|int|bigint)\(\d+\)/i', '$1', $type));
        foreach (explode("\n", $definition) as $line) {
            $line = rtrim(trim($line), ',');
            if (preg_match('/^(PRIMARY KEY|UNIQUE KEY|KEY)\s+(?:(\w+)\s*)?\(([^)]+)\)$/', $line, $key)) {
                $name = $key[1] === 'PRIMARY KEY' ? 'PRIMARY' : $key[2];
                $expected = array_map('trim', explode(',', $key[3]));
                $actual = $indexes[$name] ?? null;
                if ($actual) { ksort($actual['columns']); }
                if (!$actual || array_values($actual['columns']) !== $expected || $actual['unique'] !== ($key[1] !== 'KEY')) {
                    throw new \RuntimeException('Required own index is missing or incompatible.');
                }
                continue;
            }
            if (!preg_match('/^(\w+)\s+(\w+(?:\(\d+\))?(?: unsigned)?)/', $line, $expected)) {
                throw new \LogicException('Invalid own schema definition.');
            }
            $column = $columns[$expected[1]] ?? null;
            $nullable = !str_contains($line, 'NOT NULL');
            $autoIncrement = str_contains($line, 'AUTO_INCREMENT');
            if (!$column || $normalizeType($column['Type']) !== $normalizeType($expected[2]) || ($column['Null'] === 'YES') !== $nullable || str_contains($column['Extra'], 'auto_increment') !== $autoIncrement) {
                throw new \RuntimeException('Required own column is missing or incompatible.');
            }
            if (preg_match('/COLLATE (\w+)/', $line, $collation) && $column['Collation'] !== $collation[1]) {
                throw new \RuntimeException('Required own identifier collation is missing.');
            }
            if (preg_match("/DEFAULT '([^']*)'/", $line, $default) && $column['Default'] !== $default[1]) {
                throw new \RuntimeException('Required own column default is missing.');
            }
        }
    }
}
