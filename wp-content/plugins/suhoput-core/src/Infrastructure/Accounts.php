<?php
declare(strict_types=1);
namespace Suhoput\Core\Infrastructure;

/** Own uniqueness authority; WordPress remains the password/session authority. */
final class Accounts
{
    public const RULE = 'На один email можно зарегистрировать только один аккаунт: розничный или оптовый';
    public const DUPLICATE = 'Этот email уже зарегистрирован. Войдите в аккаунт или восстановите пароль';
    private static ?string $lock = null;
    private static ?array $pending = null;
    private static ?string $failure = null;
    private static ?int $reconnectRetries = null;
    private static ?bool $previousSuppression = null;

    public static function boot(): void
    {
        add_filter('pre_user_email', static fn($email) => strtolower(trim((string)$email)), PHP_INT_MAX);
        add_filter('wp_pre_insert_user_data', [self::class,'prepare'], PHP_INT_MAX, 4);
        add_action('user_register', [self::class,'complete'], PHP_INT_MIN);
        add_action('profile_update', [self::class,'complete'], PHP_INT_MIN);
        add_action('shutdown', [self::class,'abort'], PHP_INT_MAX);
    }

    public static function normalize(string $email): ?string
    {
        $email=strtolower(trim($email));
        return strlen($email) <= 100 && is_email($email) ? $email : null;
    }

    /** Called before WooCommerce validates/saves a form; serializes its subsequent checks. */
    public static function validate(string $email, int $userId=0): ?string
    {
        if (self::$pending !== null) { return 'Не удалось сохранить аккаунт. Повторите попытку.'; }
        self::$failure=null;
        $key=self::normalize($email);
        if ($key === null) { return 'Укажите корректный email.'; }
        if (!self::acquire()) { return 'Не удалось сохранить аккаунт. Повторите попытку.'; }
        global $wpdb;
        $table=$wpdb->prefix.'suhoput_accounts';
        $old=$wpdb->suppress_errors(true);
        try {
            // Read the database directly: another request may have invalidated an email cache.
            $owners=$wpdb->get_col($wpdb->prepare("SELECT ID FROM {$wpdb->users} WHERE BINARY LOWER(TRIM(user_email))=%s",$key));
            if ($wpdb->last_error) { return self::reject('Не удалось сохранить аккаунт. Повторите попытку.'); }
            foreach ($owners as $owner) { if ((int)$owner !== $userId) { return self::reject(self::DUPLICATE); } }
            $claim=$wpdb->get_row($wpdb->prepare("SELECT user_id FROM {$table} WHERE email_key=%s",$key),ARRAY_A);
            if ($wpdb->last_error) { return self::reject('Не удалось сохранить аккаунт. Повторите попытку.'); }
            if ($claim && ($userId === 0 || $claim['user_id'] === null || (int)$claim['user_id'] !== $userId)) { return self::reject(self::DUPLICATE); }
            return null;
        } finally { $wpdb->suppress_errors($old); }
    }

    private static function reject(string $message): string
    {
        self::$failure=$message;
        self::abort();
        return $message;
    }

    private static function acquire(): bool
    {
        if (self::$lock !== null) { return true; }
        global $wpdb;
        $name='suhoput_accounts_'.substr(hash('sha256',DB_NAME.'|'.$wpdb->prefix),0,24);
        if ((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s,10)',$name)) !== 1) { return false; }
        self::$lock=$name;
        return true;
    }

    public static function prepare(array $data, bool $update, ?int $userId, array $raw): array
    {
        $id=$update ? (int)$userId : 0;
        $key=self::normalize((string)($data['user_email'] ?? ''));
        $error=self::validate((string)($data['user_email'] ?? ''),$id);
        if ($error !== null) { self::notice($error); return []; }
        global $wpdb;
        $table=$wpdb->prefix.'suhoput_accounts';
        $old=$wpdb->suppress_errors(true);
        try {
            // No caller's transaction may be implicitly committed by START TRANSACTION.
            if ((int)$wpdb->get_var('SELECT @@in_transaction') !== 0) { throw new \RuntimeException('Nested account transaction.'); }
            foreach ([$wpdb->users,$wpdb->usermeta,$table] as $name) {
                $engine=$wpdb->get_var($wpdb->prepare('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s',$name));
                if (strcasecmp((string)$engine,'InnoDB') !== 0) { throw new \RuntimeException('Account storage must be transactional.'); }
            }
            if ($wpdb->query('START TRANSACTION') === false) { throw new \RuntimeException('Account transaction unavailable.'); }
            self::$pending=['key'=>$key,'user_id'=>$id,'expected'=>$data,'previous'=>null];
            self::$previousSuppression=$old;
            // WordPress retries errno 2006 on a new autocommit connection. Never replay
            // any part of this transaction there. The query guard checks ownership
            // and the previous SQL error before WordPress can ignore a failed write.
            self::$reconnectRetries=(int)$wpdb->reconnect_retries;
            $wpdb->reconnect_retries=0;
            add_filter('query',[self::class,'guardQuery'],PHP_INT_MAX);
            $existing=$id ? $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE user_id=%d",$id),ARRAY_A) : null;
            if ($wpdb->last_error) { throw new \RuntimeException('Account lookup failed.'); }
            if ($existing) {
                // Never infer or overwrite the sole buyer type/counterparty from request fields or roles.
                if ($wpdb->update($table,['email_key'=>$key],['id'=>$existing['id']]) === false) { throw new \RuntimeException('Account claim failed.'); }
            } else {
                if ($wpdb->insert($table,['email_key'=>$key,'user_id'=>$id ?: null,'buyer_type'=>'retail','access_enabled'=>1]) !== 1) { throw new \RuntimeException('Account claim failed.'); }
            }
            $data['user_email']=$key;
            self::$pending['expected']=$data;
            if ($update) {
                $previous=$wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->users} WHERE ID=%d",$id),ARRAY_A);
                if (!$previous || $wpdb->last_error) { throw new \RuntimeException('Account lookup failed.'); }
                self::$pending['previous']=$previous;
                // WP 7.1 clears this field after the pre-insert filter on credential changes.
                if ($previous['user_email'] !== $key || $previous['user_pass'] !== $data['user_pass']) { self::$pending['expected']['user_activation_key']=''; }
            }
            return $data;
        } catch (\Throwable $e) {
            self::reject('Не удалось сохранить аккаунт. Повторите попытку.');
            self::notice(self::$failure);
            return [];
        } finally { if (self::$pending === null) { $wpdb->suppress_errors($old); } }
    }

    public static function complete(int $userId): void
    {
        if (self::$pending === null) { return; }
        global $wpdb;
        $table=$wpdb->prefix.'suhoput_accounts';
        self::$pending['user_id']=$userId;
        try {
            $key=self::$pending['key'];
            // wp_insert_user/wp_update_user do not check the SQL write result in this version.
            $stored=$userId > 0 ? $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->users} WHERE ID=%d",$userId),ARRAY_A) : null;
            if (!$stored || $wpdb->last_error) { throw new \RuntimeException('WordPress account write not confirmed.'); }
            foreach (self::$pending['expected'] as $field=>$value) {
                if (!array_key_exists($field,$stored) || (string)$stored[$field] !== (string)$value) { throw new \RuntimeException('WordPress account write not confirmed.'); }
            }
            if ($wpdb->update($table,['user_id'=>$userId],['email_key'=>$key]) === false ||
                (int)$wpdb->get_var($wpdb->prepare("SELECT user_id FROM {$table} WHERE email_key=%s",$key)) !== $userId ||
                $wpdb->query('COMMIT') === false) {
                throw new \RuntimeException('Account commit failed.');
            }
            self::$pending=null;
        } catch (\Throwable $e) {
            self::abort();
            throw new \RuntimeException('Не удалось сохранить аккаунт. Повторите попытку.');
        } finally { self::abort(); }
    }

    public static function abort(): void
    {
        global $wpdb;
        remove_filter('query',[self::class,'guardQuery'],PHP_INT_MAX);
        if (self::$pending !== null) {
            $id=self::$pending['user_id'];
            // Do not invoke wpdb's retry/bail path during rollback of a lost connection.
            try { if ($wpdb->dbh instanceof \mysqli) { @mysqli_query($wpdb->dbh,'ROLLBACK'); } } catch (\Throwable $e) { /* Server already rolled it back. */ }
            $cacheRows=[self::$pending['expected'],self::$pending['previous']];
            self::$pending=null;
            // Numeric clean_user_cache reads the DB. Invalidate known old/new keys
            // directly, including metadata that WP may have cached before rollback.
            if ($id) { wp_cache_delete($id,'users'); wp_cache_delete($id,'user_meta'); }
            foreach ($cacheRows as $row) {
                if (!$row) { continue; }
                foreach (['user_login'=>'userlogins','user_nicename'=>'userslugs','user_email'=>'useremail'] as $field=>$group) {
                    if (!empty($row[$field])) { wp_cache_delete($row[$field],$group); }
                }
            }
            wp_cache_set_users_last_changed();
        }
        if (self::$reconnectRetries !== null) {
            $wpdb->reconnect_retries=self::$reconnectRetries; self::$reconnectRetries=null;
            $wpdb->check_connection(false);
        }
        if (self::$lock !== null) {
            try {
                if ($wpdb->dbh instanceof \mysqli) { $name=mysqli_real_escape_string($wpdb->dbh,self::$lock); @mysqli_query($wpdb->dbh,"SELECT RELEASE_LOCK('{$name}')"); }
            } catch (\Throwable $e) { /* Lost connections release their locks. */ }
            self::$lock=null;
        }
        if (self::$previousSuppression !== null) {
            $wpdb->suppress_errors(self::$previousSuppression); self::$previousSuppression=null;
        }
    }

    public static function guardQuery(string $sql): string
    {
        if (self::$pending === null) { return $sql; }
        global $wpdb;
        if (self::$pending['user_id'] === 0 && $wpdb->insert_id > 0 && str_starts_with((string)$wpdb->last_query,"INSERT INTO `{$wpdb->users}`")) { self::$pending['user_id']=(int)$wpdb->insert_id; }
        try {
            if ($wpdb->last_error || !($wpdb->dbh instanceof \mysqli)) { throw new \RuntimeException(); }
            $name=mysqli_real_escape_string($wpdb->dbh,self::$lock ?? '');
            $result=@mysqli_query($wpdb->dbh,"SELECT @@in_transaction AS active, IS_USED_LOCK('{$name}')=CONNECTION_ID() AS owned");
            $row=$result instanceof \mysqli_result ? $result->fetch_assoc() : null;
            if ($result instanceof \mysqli_result) { $result->free(); }
            if (!$row || (int)$row['active'] !== 1 || (int)$row['owned'] !== 1) { throw new \RuntimeException(); }
        } catch (\Throwable $e) {
            self::abort();
            throw new \RuntimeException('Не удалось сохранить аккаунт. Повторите попытку.');
        }
        return $sql;
    }

    private static function notice(string $message): void
    {
        if (function_exists('WC') && WC()->session !== null && did_action('woocommerce_init')) { wc_add_notice(self::message($message),'error'); }
    }

    public static function message(string $message): string
    {
        $text=esc_html($message);
        if ($message === self::DUPLICATE) {
            $text.=' <a href="'.esc_url(wc_get_page_permalink('myaccount')).'">Вход</a> · <a href="'.esc_url(wc_lostpassword_url()).'">Восстановление пароля</a>';
        }
        return $text;
    }

    /** The future invitation handler must stop on a retail conflict, never convert it. */
    public static function invitationConflict(string $email): ?\WP_Error
    {
        $key=self::normalize($email);
        if ($key === null) { return new \WP_Error('invalid_email','Укажите корректный email.'); }
        global $wpdb;
        $row=$wpdb->get_row($wpdb->prepare("SELECT buyer_type FROM {$wpdb->prefix}suhoput_accounts WHERE email_key=%s",$key),ARRAY_A);
        if ($wpdb->last_error) { return new \WP_Error('account_unavailable','Не удалось проверить аккаунт.'); }
        if ($row && $row['buyer_type'] === 'retail') { return new \WP_Error('retail_conflict','Этот email принадлежит розничному аккаунту. Тип автоматически не изменяется.'); }
        if (!$row && email_exists($key)) { return new \WP_Error('existing_account','Этот email уже принадлежит аккаунту. Требуется проверка привязки.'); }
        return null;
    }
}
