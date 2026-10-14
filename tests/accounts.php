<?php
if (wp_get_environment_type() !== 'local' || !defined('SUHOPUT_LOCAL_SAFETY')) { throw new RuntimeException('Local tests only.'); }
global $wpdb;
$table = $wpdb->prefix.'suhoput_accounts';
$tag = 'acct-'.substr(wp_generate_uuid4(),0,8);
$users = [];
$checks = 0;
$assert = static function (bool $ok, string $name) use (&$checks): void { if (!$ok) { throw new RuntimeException('FAIL: '.$name); } ++$checks; };
$create = static function (string $suffix, string $email) use ($tag, &$users) {
    $id = wp_insert_user(['user_login'=>$tag.'-'.$suffix,'user_email'=>$email,'user_pass'=>wp_generate_password(28),'role'=>'customer']);
    if (!is_wp_error($id)) { $users[]=$id; }
    return $id;
};
$row = static fn(int $id) => $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE user_id=%d",$id),ARRAY_A);
try {
    $email=$tag.'@example.invalid';
    $id=$create('one','  '.strtoupper($email).'  ');
    $assert(!is_wp_error($id),'User created');
    $assert(get_userdata($id)->user_email === $email,'Email trimmed and lowercased in WordPress');
    $assert($row($id)['email_key'] === $email,'Unique registry bound to WordPress user');
    $assert($row($id)['buyer_type'] === 'retail' && (int)$row($id)['access_enabled'] === 1,'Registration creates only retail');
    $assert(is_wp_error($create('dup',strtoupper($email))),'Duplicate rejected');
    $assert(is_wp_error($create('invalid',$tag.' not email')),'Invalid email rejected');
    $plus=$create('plus',$tag.'+one@example.invalid');
    $dot=$create('dot',str_replace('acct-','a.cct-',$tag).'@example.invalid');
    $assert(!is_wp_error($plus) && !is_wp_error($dot),'Provider plus and dots remain distinct');
    $id2=$create('two',$tag.'-two@example.invalid');
    $assert(is_wp_error(wp_update_user(['ID'=>$id2,'user_email'=>$email])),'Email change to existing account rejected');
    $assert($row($id2)['email_key'] === $tag.'-two@example.invalid','Conflict preserves old registry');
    $changed=$tag.'-changed@example.invalid';
    $assert(wp_update_user(['ID'=>$id2,'user_email'=>' '.strtoupper($changed).' ']) === $id2,'Email change accepted');
    $assert(get_userdata($id2)->user_email === $changed && $row($id2)['email_key'] === $changed,'Email and registry move together');
    $assert(!is_wp_error($create('reuse',$tag.'-two@example.invalid')),'Previous email becomes available');
    $assert(is_wp_error(wp_update_user(['ID'=>$id2,'user_email'=>''])),'Empty email cannot remove uniqueness');
    $assert($row($id2)['email_key'] === $changed,'Invalid update preserves registry');
    $assert(is_wp_error(\Suhoput\Core\Infrastructure\Accounts::invitationConflict($email)),'Retail invitation gives explicit conflict');
    $assert($row($id)['buyer_type'] === 'retail','Invitation does not change type');
    $wpdb->update($table,['buyer_type'=>'wholesale','counterparty_id'=>$tag,'access_enabled'=>1],['user_id'=>$id2]);
    $assert(wp_update_user(['ID'=>$id2,'user_email'=>$tag.'-wholesale@example.invalid']) === $id2,'Wholesale email may change');
    $assert($row($id2)['buyer_type'] === 'wholesale' && $row($id2)['counterparty_id'] === $tag,'Email update preserves sole type and historical link');
    $assert(is_wp_error($create('wholesale-dup',$tag.'-wholesale@example.invalid')),'Retail registration cannot duplicate wholesale');
    $wpdb->insert($table,['email_key'=>$tag.'-invite@example.invalid','buyer_type'=>'wholesale','counterparty_id'=>$tag.'-pending']);
    $assert(is_wp_error($create('invite',$tag.'-invite@example.invalid')),'Pending invitation email cannot be taken by retail');
    $password=wp_generate_password(28);
    $assert(wp_update_user(['ID'=>$id,'user_pass'=>$password]) === $id,'Password update uses WordPress');
    $assert(wp_authenticate($email,$password) instanceof WP_User,'Email login works');
    $assert(is_wp_error(wp_authenticate($email,wp_generate_password(28))),'Wrong password rejected');
    $user=get_userdata($id); $key=get_password_reset_key($user);
    $assert(!is_wp_error($key) && check_password_reset_key($key,$user->user_login) instanceof WP_User,'Reset token works');
    $replacement=wp_generate_password(28); reset_password($user,$replacement);
    $assert(is_wp_error(check_password_reset_key($key,$user->user_login)),'Reset token becomes unusable');
    $assert(is_wp_error(wp_authenticate($email,$password)) && wp_authenticate($email,$replacement) instanceof WP_User,'Password recovery changes login credential');
    $key=get_password_reset_key(get_userdata($id));
    $assert(wp_update_user(['ID'=>$id,'user_email'=>$tag.'-keychange@example.invalid']) === $id,'Email can change while reset link is outstanding');
    $assert(is_wp_error(check_password_reset_key($key,get_userdata($id)->user_login)),'Email change invalidates outstanding reset link');
    $key=get_password_reset_key(get_userdata($id));
    $assert(wp_update_user(['ID'=>$id,'user_pass'=>wp_generate_password(28)]) === $id,'Password can change while reset link is outstanding');
    $assert(is_wp_error(check_password_reset_key($key,get_userdata($id)->user_login)),'Password change invalidates outstanding reset link');
    $assert(get_option('woocommerce_enable_myaccount_registration') === 'yes','Retail form enabled');
    $assert(get_option('woocommerce_enable_guest_checkout') === 'yes' && get_option('woocommerce_enable_signup_and_login_from_checkout') === 'no','Guest checkout remains optional');
    // Inject failure at the actual WordPress INSERT, after the unique registry claim.
    $failedEmail=$tag.'-failed@example.invalid';
    $faultSeen=false;
    $fault=static function ($sql) use ($wpdb,&$faultSeen) { if (str_starts_with($sql,"INSERT INTO `{$wpdb->users}`")) { $faultSeen=true; return 'SELECT suhoput_test_unknown_column'; } return $sql; };
    $old=$wpdb->suppress_errors(true); add_filter('query',$fault);
    try { $failed=$create('failed',$failedEmail); } catch (RuntimeException $e) { $failed=new WP_Error('failed'); } finally { remove_filter('query',$fault); $wpdb->suppress_errors($old); }
    if (class_exists(\Suhoput\Core\Infrastructure\Accounts::class)) { \Suhoput\Core\Infrastructure\Accounts::abort(); }
    $assert($faultSeen,'Actual WordPress INSERT fault injected');
    $assert(!$failed || is_wp_error($failed),'WordPress insert failure cannot report a positive user ID');
    $assert((int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE email_key=%s",$failedEmail)) === 0,'Failed insert rolls back claim');
    $assert(!is_wp_error($create('retry',$failedEmail)),'Failed registration can be retried safely');
    echo 'PASS: '.$checks." account checks (local WordPress/WooCommerce, real database)\n";
} finally {
    if (class_exists(\Suhoput\Core\Infrastructure\Accounts::class)) { \Suhoput\Core\Infrastructure\Accounts::abort(); }
    require_once ABSPATH.'wp-admin/includes/user.php';
    foreach ($users as $userId) { $wpdb->delete($table,['user_id'=>$userId]); wp_delete_user($userId); }
    $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE counterparty_id IN (%s,%s)",$tag,$tag.'-pending'));
    $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE email_key LIKE %s",$wpdb->esc_like($tag).'%@example.invalid'));
}
