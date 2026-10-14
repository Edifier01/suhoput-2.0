<?php defined('ABSPATH') || exit; ?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head><meta charset="<?php bloginfo('charset'); ?>"><meta name="viewport" content="width=device-width, initial-scale=1"><?php wp_head(); ?></head>
<body <?php body_class(); ?>><?php wp_body_open(); ?>
<main><h1><?php echo esc_html(get_bloginfo('name')); ?></h1>
<?php while (have_posts()) { the_post(); the_title('<h2>', '</h2>'); the_content(); } ?>
</main><?php wp_footer(); ?></body></html>
