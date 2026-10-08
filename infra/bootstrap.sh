#!/bin/sh
set -eu
if ! wp core is-installed >/dev/null 2>&1; then
  wp core install --url=http://localhost:18880 --title='Suhoput local' --admin_user=local-admin --admin_password="$LOCAL_ADMIN_PASSWORD" --admin_email=local-admin@example.invalid --skip-email
fi
if ! wp plugin is-installed woocommerce >/dev/null 2>&1; then
  wp plugin install /packages/woocommerce.11.2.0.zip
fi
if [ "$(wp plugin get woocommerce --field=version)" != '11.2.0' ]; then
  echo 'Unexpected WooCommerce version; bootstrap stopped.' >&2
  exit 1
fi
wp plugin activate woocommerce
wp plugin activate suhoput-core suhoput-moysklad
wp theme activate suhoput
wp option update timezone_string Europe/Moscow
wp option update woocommerce_currency RUB
wp option update woocommerce_prices_include_tax yes
wp option update woocommerce_custom_orders_table_enabled yes
wp option update woocommerce_custom_orders_table_data_sync_enabled no
wp option update woocommerce_enable_coupons no
wp option update woocommerce_enable_guest_checkout yes
wp rewrite structure '/%postname%/'
wp eval 'if (!get_option("woocommerce_cart_page_id")) { WC_Install::create_pages(); } foreach (["cart"=>"[woocommerce_cart]","checkout"=>"[woocommerce_checkout]"] as $key=>$content) { $id=get_option("woocommerce_".$key."_page_id"); if ($id) { wp_update_post(["ID"=>$id,"post_content"=>$content]); } }'
echo 'Local bootstrap complete. Payment modules were not installed.'
