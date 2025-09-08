<?php
/**
 * The onboard model class.
 *
 * @package WP_Defender\Model
 */

namespace WP_Defender\Model;

/**
 * Class Onboard.
 *
 * Provides methods to check if the site is newly created.
 */
class Onboard {
	/**
	 * Checks if the site is newly created.
	 *
	 * @return bool Returns true if the site is newly created, false otherwise.
	 */
	public static function maybe_show_onboarding(): bool {
		// First we need to check if the site is newly create.
		if ( ! is_multisite() ) {
			$res = get_option( 'wp_defender_shown_activator' );
		} else {
			$res = get_site_option( 'wp_defender_shown_activator' );
		}
		// Get '1' for direct SQL request if Onboarding was already.
		if ( empty( $res ) ) {
			return true;
		}

		return false;
	}
}
