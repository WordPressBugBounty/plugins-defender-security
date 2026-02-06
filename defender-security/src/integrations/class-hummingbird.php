<?php
/**
 * Handles interactions with Hummingbird.
 *
 * @since      2.6.1
 * @package WP_Defender\Integrations
 */

namespace WP_Defender\Integrations;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hummingbird integration module.
 */
class Hummingbird {

	/**
	 * Check if Hummingbird is active.
	 *
	 * @return bool
	 */
	public function is_hummingbird_enabled() {
		return class_exists( 'Hummingbird\\WP_Hummingbird' );
	}

	/**
	 * Check if Hummingbird has lazy load comments enabled.
	 *
	 * @return bool
	 */
	public function is_lazy_load_comments_enabled() {
		if ( ! $this->is_hummingbird_enabled() ) {
			return false;
		}

		$settings = is_multisite() ? get_site_option( 'wphb_settings', array() ) : get_option(
			'wphb_settings',
			array()
		);
		if ( ! is_array( $settings ) || array() === $settings ) {
			return false;
		}

		return isset( $settings['advanced']['lazy_load']['enabled'] ) && true === $settings['advanced']['lazy_load']['enabled'];
	}
}
