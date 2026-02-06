<?php
/**
 * Handles interactions with BuddyPress plugin.
 *
 * @package WP_Defender\Integrations
 */

namespace WP_Defender\Integrations;

if ( ! defined( 'ABSPATH' ) ) {
	die;
}

/**
 * Buddypress integration module.
 *
 * @since 3.3.0
 */
class Buddypress {

	public const REGISTER_FORM = 'buddypress_register', NEW_GROUP_FORM = 'buddypress_new group';

	/**
	 * Check if Buddypress is activated.
	 *
	 * @return bool
	 */
	public function is_activated(): bool {
		return class_exists( 'buddypress' );
	}

	/**
	 * Get the Defender forms.
	 *
	 * @return array
	 */
	public static function get_forms(): array {
		return array(
			self::REGISTER_FORM  => esc_html__( 'Registration', 'defender-security' ),
			self::NEW_GROUP_FORM => esc_html__( 'Add new group', 'defender-security' ),
		);
	}

	/**
	 * Detects if the request is coming from a BuddyPress login/registration context.
	 *
	 * @return bool
	 */
	public function is_login_context(): bool {
		if ( ! $this->is_activated() ) {
			return false;
		}

		// Check if this is a POST request with form data.
		$post_data = defender_get_data_from_request( null, 'p' );
		if ( 0 === count( $post_data ) ) {
			return false;
		}

		// Check referer against BuddyPress root URL.
		$referer     = wp_get_referer();
		$redirect_to = defender_get_data_from_request( 'redirect_to', 'p' );
		return $referer === $redirect_to;
	}
}
