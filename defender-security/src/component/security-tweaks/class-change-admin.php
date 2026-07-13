<?php
/**
 * Security Tweaks Component for changing the default 'admin' username.
 *
 * @package    WP_Defender\Component\Security_Tweaks
 */

namespace WP_Defender\Component\Security_Tweaks;

use WP_User;
use WP_Error;
use Calotes\Helper\HTTP;
use Calotes\Component\Response;

/**
 * Handle the security tweak of changing the default 'admin' username to a user-defined one.
 */
class Change_Admin extends Abstract_Security_Tweaks {

	/**
	 * Slug identifier for the component.
	 *
	 * @var string
	 */
	public string $slug = 'replace-admin-username';

	/**
	 * Check whether the issue has been resolved or not.
	 *
	 * @return bool
	 */
	public function check(): bool {
		return $this->is_resolved();
	}

	/**
	 * If the return is true or Response, we add it to resolve list. WP_Error if any error.
	 *
	 * @return bool|WP_Error|Response
	 */
	public function process() {
		$username = HTTP::post( 'username' );
		$is_valid = $this->validate( $username );

		if ( is_wp_error( $is_valid ) ) {
			return $is_valid;
		}

		return $this->update_username( $username );
	}

	/**
	 * This is for un-do stuff that has be done in @process.
	 *
	 * @return bool
	 */
	public function revert(): bool {
		return true;
	}

	/**
	 * Shield up.
	 *
	 * @return bool
	 */
	public function shield_up(): bool {
		return true;
	}

	/**
	 * Check whether the issue is resolved or not.
	 *
	 * @return bool
	 */
	private function is_resolved() {
		return ! $this->get_user_with_admin_username();
	}

	/**
	 * Get user with admin username.
	 *
	 * @return WP_User|false on failure
	 */
	private function get_user_with_admin_username() {
		return get_user_by( 'login', 'admin' );
	}

	/**
	 * Validate username.
	 *
	 * @param  string $username  to validate.
	 *
	 * @return bool|WP_Error on failure
	 */
	private function validate( $username ) {
		if ( ! is_string( $username ) || '' === $username ) {
			return new WP_Error( 'defender_invalid_username', wp_strip_all_tags( __( 'The username can\'t be empty!', 'defender-security' ) ) );
		}

		if ( 'admin' === strtolower( $username ) ) {
			return new WP_Error(
				'defender_invalid_username',
				wp_strip_all_tags( __( 'You can\'t use admin as a username again!', 'defender-security' ) )
			);
		}

		if ( ! validate_username( $username ) ) {
			return new WP_Error( 'defender_invalid_username', wp_strip_all_tags( __( 'The username is invalid!', 'defender-security' ) ) );
		}

		if ( username_exists( $username ) ) {
			return new WP_Error( 'defender_invalid_username', wp_strip_all_tags( __( 'The username already exists!', 'defender-security' ) ) );
		}

		return true;
	}

	/**
	 * Updates the 'admin' username to a new username.
	 * Performs the update in the database and handles multisite admin updates if applicable.
	 *
	 * @param  string $username  The new username.
	 *
	 * @return bool|WP_Error|Response True on success, WP_Error on database error, Response on logout requirement.
	 */
	private function update_username( $username ) {
		global $wpdb;
		$user = $this->get_user_with_admin_username();

		$ret = $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->users,
			array( 'user_login' => trim( $username ) ),
			array( 'ID' => $user->ID )
		);
		if ( ! $ret ) {
			return new WP_Error( 'update_error', $wpdb->last_error );
		}

		if ( is_multisite() ) {
			$site_admins = get_site_option( 'site_admins' );

			if ( is_array( $site_admins ) ) {
				$pos = array_search( 'admin', array_map( 'strtolower', $site_admins ), true );

				if ( false !== $pos ) {
					$site_admins[ $pos ] = $username;
					update_site_option( 'site_admins', $site_admins );
				}
			}
		}
		clean_user_cache( $user );
		// Log the user out only if it's the user with 'admin' username.
		if ( get_current_user_id() !== $user->ID ) {
			return true;
		}
		if ( defined( 'WP_DEFENDER_TESTING' ) && true === constant( 'WP_DEFENDER_TESTING' ) ) {
			// Testing.
			return true;
		}
		$interval = 5;
		$redirect = $this->get_login_url();

		return new Response(
			true,
			array(
				'message'  => sprintf(
				/* translators: 1. Redirect link. 2. Line break. 3. Interval. */
					esc_html__(
						'Your admin name has changed. You will need to %1$s.%2$s This will auto reload after %3$s seconds.',
						'defender-security'
					),
					'<a href="' . $redirect . '"><strong>' . esc_html__( 're-login', 'defender-security' ) . '</strong></a>',
					'<br>',
					'<span class="hardener-timer">' . $interval . '</span>'
				),
				'redirect' => $redirect,
				'interval' => $interval,
			)
		);
	}

	/**
	 * Get the login url.
	 *
	 * @return string
	 */
	private function get_login_url(): string {
		return wp_login_url( network_admin_url( 'admin.php?page=wdf-hardener' ) );
	}

	/**
	 * Retrieve the tweak's label.
	 *
	 * @return string
	 */
	public function get_label(): string {
		return esc_html__( 'Change admin account', 'defender-security' );
	}

	/**
	 * Get the error reason.
	 *
	 * @return string
	 */
	public function get_error_reason(): string {
		return wp_kses(
			__( '<strong>Your account uses the default “admin” username,</strong> and may attract login attacks.', 'defender-security' ),
			array(
				'strong' => array(),
			)
		);
	}

	/**
	 * Return a summary data of this tweak.
	 *
	 * @return array
	 */
	public function to_array(): array {
		$admin_user   = $this->get_user_with_admin_username();
		$current_user = wp_get_current_user();
		$username     = $admin_user ? $admin_user->user_login : $current_user->user_login;
		$error_reason = wp_kses(
			sprintf(
				/* translators: %s: Username. */
				__( '<strong>Your account uses the default "%s" username,</strong> and may attract login attacks.', 'defender-security' ),
				esc_html( $username )
			),
			array(
				'strong' => array(),
			)
		);

		return array(
			'slug'             => $this->slug,
			'title'            => $this->get_label(),
			'errorReason'      => $error_reason,
			'successReason'    => wp_strip_all_tags( __( 'Username is up to date.', 'defender-security' ) ),
			'misc'             => array(
				'show_revert_button' => false,
				'show_action_button' => true,
				'admin_username'     => $username,
			),
			'bulk_description' => wp_strip_all_tags( __( 'Brute force attacks often rely on common usernames and guessed passwords. Create a new admin username to make your site harder to target and help protect your login area.', 'defender-security' ) ),
			'bulk_title'       => wp_strip_all_tags( __( 'Admin User', 'defender-security' ) ),
		);
	}
}
