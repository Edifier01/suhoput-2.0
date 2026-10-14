<?php
declare(strict_types=1);
namespace Suhoput\Core\Commerce;

final class Settings
{
    public static function boot(): void
    {
        add_action('admin_menu',static function(): void { add_submenu_page('woocommerce','Гостевые ограничения','Гостевые ограничения','manage_suhoput','suhoput-commerce',[self::class,'page']); });
        add_filter('option_page_capability_suhoput-commerce',static fn() => 'manage_suhoput');
        add_action('admin_init',static function(): void {
            register_setting('suhoput-commerce','suhoput_guest_limits',['type'=>'array','show_in_rest'=>false,'sanitize_callback'=>static function($value): array {
                try { return GuestLimits::validate($value); }
                catch (\InvalidArgumentException $error) { add_settings_error('suhoput_guest_limits','invalid','Укажите положительные целые значения. Общий лимит IP должен быть не меньше лимита браузера.'); return GuestLimits::settings(); }
            }]);
        });
    }

    public static function page(): void
    {
        if (!current_user_can('manage_suhoput')) { wp_die('Недостаточно прав.','',['response'=>403]); }
        $settings=GuestLimits::settings();
        echo '<div class="wrap"><h1>Гостевые ограничения</h1><p>Лимит общего IP учитывает нескольких покупателей. Изменение настроек не освобождает существующие удержания.</p>';
        settings_errors(); echo '<form method="post" action="options.php">'; settings_fields('suhoput-commerce');
        foreach (['actor_rate'=>'Действий браузера за окно','ip_rate'=>'Действий общего IP за окно','window'=>'Окно, секунд (1–3600)','actor_holds'=>'Активных неоплаченных удержаний браузера','ip_holds'=>'Активных неоплаченных удержаний общего IP'] as $key=>$label) {
            echo '<p><label>'.esc_html($label).' <input type="number" min="1" max="'.($key === 'window' ? 3600 : 10000).'" name="suhoput_guest_limits['.esc_attr($key).']" value="'.esc_attr((string)$settings[$key]).'"></label></p>';
        }
        submit_button(); echo '</form></div>';
    }
}
