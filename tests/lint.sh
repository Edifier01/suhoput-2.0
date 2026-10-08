#!/bin/sh
set -eu
find /var/www/html/wp-content/plugins/suhoput-core /var/www/html/wp-content/plugins/suhoput-moysklad /var/www/html/wp-content/themes/suhoput /tests -name '*.php' -print |
while IFS= read -r file; do php -l "$file"; done
php -l /var/www/html/wp-content/mu-plugins/suhoput-local-safety.php
