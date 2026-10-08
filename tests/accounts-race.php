<?php
if (wp_get_environment_type() !== 'local' || !defined('SUHOPUT_LOCAL_SAFETY')) { throw new RuntimeException('Local tests only.'); }
global $wpdb;
[$tag,$scenario,$mode]=$args;
if (!preg_match('/\Arace-[a-f0-9]{12}\z/',$tag) || !in_array($scenario,['register','update','mixed','crash'],true)) { throw new RuntimeException('Invalid fixture.'); }
$name='suhoput_test_'.$tag;
$table=$wpdb->prefix.'suhoput_accounts';
$target=$tag.'@example.invalid';
$state=get_option($name,[]);
$create=static function ($worker,$email) use ($tag) { return wp_insert_user(['user_login'=>$tag.'-'.$worker,'user_email'=>$email,'user_pass'=>wp_generate_password(28),'role'=>'customer']); };
if ($mode === 'setup') {
    $state=['ids'=>[]];
    if ($scenario === 'update' || $scenario === 'mixed') {
        foreach ($scenario === 'update' ? [1,2] : [2] as $n) {
            $id=$create($n,$tag.'-'.$n.'@example.invalid'); if (is_wp_error($id)) { throw new RuntimeException('Setup failed.'); }
            $state['ids'][$n]=$id;
        }
    }
    add_option($name,$state,'','no'); echo "SETUP\n"; return;
}
if ($mode === 'cleanup') {
    \Suhoput\Core\Infrastructure\Accounts::abort();
    require_once ABSPATH.'wp-admin/includes/user.php';
    $ids=$wpdb->get_col($wpdb->prepare("SELECT ID FROM {$wpdb->users} WHERE user_login IN (%s,%s)",$tag.'-1',$tag.'-2'));
    foreach ($ids as $id) { $wpdb->delete($table,['user_id'=>$id]); wp_delete_user($id); }
    $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE email_key LIKE %s",$wpdb->esc_like($tag).'%@example.invalid'));
    foreach ([$name,$name.'_1',$name.'_2'] as $option) { delete_option($option); }
    echo "CLEANUP\n"; return;
}
if ($mode === 'verify' || $mode === 'verify_crash') {
    $count=(int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->users} WHERE BINARY LOWER(TRIM(user_email))=%s",$target));
    $claims=(int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE email_key=%s",$target));
    if ($count !== ($mode === 'verify' ? 1 : 0) || $claims !== $count) { throw new RuntimeException('Email uniqueness or rollback failed.'); }
    if ($count && !(int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} a JOIN {$wpdb->users} u ON a.user_id=u.ID WHERE a.email_key=%s AND BINARY u.user_email=a.email_key AND a.buyer_type='retail'",$target))) { throw new RuntimeException('Binding failed.'); }
    if ($scenario === 'update' && $mode === 'verify') {
        foreach ($state['ids'] as $id) {
            if (!(int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} a JOIN {$wpdb->users} u ON a.user_id=u.ID WHERE u.ID=%d AND BINARY a.email_key=u.user_email",$id))) { throw new RuntimeException('Losing update changed old binding.'); }
        }
    }
    echo "VERIFIED\n"; return;
}
$worker=(int)$mode;
if (!in_array($worker,[1,2],true)) { throw new RuntimeException('Invalid worker.'); }
if ($scenario === 'crash' && $worker === 1) {
    // Run after the own filter has started its transaction and claimed the email.
    add_filter('wp_pre_insert_user_data',static function ($data) { echo "CLAIM_READY\n"; flush(); sleep(30); return $data; },PHP_INT_MAX);
} elseif ($scenario !== 'crash') {
    // Both processes have already passed WordPress's email_exists before either own claim.
    add_filter('wp_pre_insert_user_data',static function ($data) use ($name,$worker,$wpdb) {
        add_option($name.'_'.$worker,true,'','no');
        $until=microtime(true)+15;
        do { $ready=(int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name IN (%s,%s)",$name.'_1',$name.'_2')); if ($ready === 2) { return $data; } usleep(20000); } while (microtime(true)<$until);
        throw new RuntimeException('Race barrier timeout.');
    },PHP_INT_MAX-1);
}
$email=$worker === 1 ? strtoupper($target) : $target;
$result=isset($state['ids'][$worker]) ? wp_update_user(['ID'=>$state['ids'][$worker],'user_email'=>$email]) : $create($worker,$email);
echo is_wp_error($result) ? "RACE_LOSE\n" : "RACE_WIN\n";
