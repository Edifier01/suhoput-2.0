<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

final class Schema
{
    public const VERSION = 2;

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
                if ($index) { $wpdb->query("ALTER TABLE {$holdsTable} DROP INDEX operation_id"); }
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
operation_id char(36) NOT NULL,
order_id bigint unsigned NOT NULL,
composition_version bigint unsigned NOT NULL,
provider varchar(64) NOT NULL,
action varchar(64) NOT NULL,
idempotency_key varchar(64) DEFAULT NULL,
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
hold_id char(36) NOT NULL,
order_id bigint unsigned NOT NULL,
composition_version bigint unsigned NOT NULL,
variant_id bigint unsigned NOT NULL,
warehouse_id varchar(191) COLLATE utf8mb4_bin NOT NULL,
quantity bigint unsigned NOT NULL,
state varchar(16) NOT NULL DEFAULT 'pending',
operation_id char(36) NOT NULL,
expires_at datetime NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY hold_id (hold_id),
UNIQUE KEY order_variant (order_id,composition_version,variant_id),
UNIQUE KEY operation_variant (operation_id,variant_id),
KEY variant_state (variant_id,state)",
            ];
            foreach ($definitions as $name => $columns) {
                dbDelta("CREATE TABLE {$p}{$name} (\n{$columns}\n) ENGINE=InnoDB {$collate};");
                if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($p . $name))) !== $p . $name) {
                    throw new \RuntimeException('Own table migration failed.');
                }
            }
            foreach (['administrator', 'shop_manager'] as $roleName) {
                get_role($roleName)?->add_cap('manage_suhoput');
            }
            update_option('suhoput_schema_version', self::VERSION, false);
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }
}
