<?php
if (wp_get_environment_type() !== 'local' || !defined('SUHOPUT_LOCAL_SAFETY')) { throw new RuntimeException('Local tests only.'); }
use Suhoput\Core\Infrastructure\Accounts;
global $wpdb;
$mode=$args[0] ?? 'password';
if (!in_array($mode,['password','crud','disconnect-insert','disconnect-update','disconnect-complete','disconnect-commit','form'],true)) { throw new RuntimeException('Unknown scenario.'); }
$tag='fail-'.substr(wp_generate_uuid4(),0,8); $email=$tag.'@example.invalid'; $table=$wpdb->prefix.'suhoput_accounts';
$checks=0; $mailCount=0; $faultSeen=false;
$assert=static function ($ok,$name) use (&$checks) { if (!$ok) { throw new RuntimeException('FAIL: '.$name); } ++$checks; };
$mail=static function ($result) use (&$mailCount) { ++$mailCount; return true; };
add_filter('pre_wp_mail',$mail);
$fault=null;
try {
    $password=wp_generate_password(28);
    $id=wp_insert_user(['user_login'=>$tag,'user_email'=>$email,'user_pass'=>$password,'role'=>'customer']);
    $assert(!is_wp_error($id),'Fixture created');
    $oldName=get_userdata($id)->display_name; $mailCount=0;
    if ($mode === 'crud') {
        $other=wp_insert_user(['user_login'=>$tag.'-other','user_email'=>$tag.'-other@example.invalid','user_pass'=>wp_generate_password(28),'role'=>'customer']);
        $customer=new WC_Customer($id); $customer->set_email($tag.'-other@example.invalid'); $customer->set_first_name('Must not persist');
        $failed=false; try { $customer->save(); } catch (Exception $e) { $failed=true; }
        $assert($failed,'WC CRUD signals conflict');
        $assert(get_userdata($id)->user_email === $email && get_user_meta($id,'first_name',true) !== 'Must not persist','CRUD conflict preserves data');
    } else {
        $disconnect=str_starts_with($mode,'disconnect-');
        $insert=$mode === 'disconnect-insert';
        $prefix=match($mode) { 'disconnect-complete'=>"SELECT * FROM {$wpdb->users} WHERE ID=", 'disconnect-commit'=>'COMMIT', default=>$insert ? "INSERT INTO `{$wpdb->users}`" : "UPDATE `{$wpdb->users}`" };
        $completedWrite=false;
        $fault=static function ($sql) use ($wpdb,$prefix,$disconnect,$mode,&$faultSeen,&$completedWrite) {
            if (str_starts_with($sql,"UPDATE `{$wpdb->users}`")) { $completedWrite=true; }
            $atComplete=$mode !== 'disconnect-complete' || (bool)array_filter(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS,12),static fn($frame)=>($frame['class'] ?? '') === Accounts::class && ($frame['function'] ?? '') === 'complete');
            if (!$faultSeen && $atComplete && str_starts_with($sql,$prefix)) {
                $faultSeen=true;
                if ($disconnect) {
                    // Kill only this test request's connection, using a separate connection.
                    [$host,$port,$socket]=$wpdb->parse_db_host(DB_HOST);
                    $killer=new mysqli($host,DB_USER,DB_PASSWORD,DB_NAME,$port ?: 3306,$socket);
                    $killer->query('KILL CONNECTION '.(int)$wpdb->dbh->thread_id); $killer->close();
                    return $sql;
                }
                return 'SELECT suhoput_test_unknown_column';
            }
            return $sql;
        };
        $old=$wpdb->suppress_errors(true); add_filter('query',$fault,PHP_INT_MAX);
        $failed=false;
        try {
            if ($mode === 'form') {
                wp_set_current_user($id); WC()->initialize_session(); wc_clear_notices();
                $_POST=['action'=>'save_account_details','save-account-details-nonce'=>wp_create_nonce('save_account_details'),'account_first_name'=>'Local','account_last_name'=>'Fixture','account_display_name'=>'Changed','account_email'=>$tag.'-changed@example.invalid'];
                $_REQUEST=$_POST;
                \Suhoput\Core\Accounts\Forms::saveAccountDetails();
                $failed=wc_notice_count('error') > 0;
                $assert(wc_notice_count('success') === 0,'Failed public form has no success');
            } elseif ($insert) {
                $result=wp_insert_user(['user_login'=>$tag.'-new','user_email'=>$tag.'-new@example.invalid','user_pass'=>wp_generate_password(28),'role'=>'customer']);
                $failed=is_wp_error($result) || !$result;
            } else {
                $result=wp_update_user(['ID'=>$id,'user_email'=>$disconnect ? $tag.'-changed@example.invalid' : $email,'user_pass'=>wp_generate_password(28),'display_name'=>'Must not persist']);
                $failed=is_wp_error($result) || !$result;
            }
        } catch (Exception $e) { if ($mode === 'form') { throw new RuntimeException('FAIL: Public form exception escaped'); } $failed=true; }
        finally { remove_filter('query',$fault,PHP_INT_MAX); $wpdb->suppress_errors($old); Accounts::abort(); }
        $assert($faultSeen,'Actual user SQL fault injected');
        if ($mode === 'disconnect-complete') { $assert($completedWrite,'Complete fault follows actual user UPDATE'); }
        $assert($failed,'Failure cannot report success');
        clean_user_cache($id);
        $assert(get_userdata($id)->user_email === $email && get_userdata($id)->display_name === $oldName,'User data unchanged');
        $assert(wp_authenticate($email,$password) instanceof WP_User,'Old password preserved');
        $assert((int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->users} WHERE user_email IN (%s,%s)",$tag.'-new@example.invalid',$tag.'-changed@example.invalid')) === 0,'No autocommit user write after connection loss');
        $assert($wpdb->get_var($wpdb->prepare("SELECT email_key FROM {$table} WHERE user_id=%d",$id)) === $email,'Registry remains consistent');
        $assert($mailCount === 0,'No success or password-change mail after failure');
        $assert(wp_update_user(['ID'=>$id,'display_name'=>'Retry succeeds']) === $id,'Safe retry works');
    }
    echo 'PASS: '.$mode.' '.$checks." account failure checks\n";
} finally {
    if ($fault) { remove_filter('query',$fault,PHP_INT_MAX); } Accounts::abort(); remove_filter('pre_wp_mail',$mail);
    require_once ABSPATH.'wp-admin/includes/user.php';
    foreach ($wpdb->get_col($wpdb->prepare("SELECT ID FROM {$wpdb->users} WHERE user_login LIKE %s",$wpdb->esc_like($tag).'%')) as $userId) { $wpdb->delete($table,['user_id'=>$userId]); wp_delete_user($userId); }
    $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE email_key LIKE %s",$wpdb->esc_like($tag).'%@example.invalid'));
}
