<?php
/**
 * Application password audit logging.
 *
 * @package WP_Defender\Component\Audit
 */

namespace WP_Defender\Component\Audit;

use WP_Application_Passwords;
use WP_Defender\Model\Audit_Log;

/**
 * Extends User_Audit to add application password tracking.
 *
 * @since 5.8.0
 */
class Application_Password_Audit extends Audit_Event {

	/**
	 * Track if we've already logged a delete all event for this request.
	 *
	 * @var array
	 */
	private static array $deletion_count = array();

	/**
	 * Track which delete all events have been logged to prevent duplicates.
	 *
	 * @var array
	 */
	private static array $logged_delete_all = array();

	/**
	 * Returns hooks including application password tracking.
	 *
	 * @return array
	 */
	public function get_hooks(): array {

		return array(
			'wp_create_application_password' => array(
				'args'        => array( 'user_id', 'new_item', 'new_password', 'args' ),
				'event_type'  => Audit_Log::EVENT_TYPE_USER,
				'context'     => User_Audit::CONTEXT_PROFILE,
				'action_type' => self::ACTION_CREATED,
				'callback'    => array( $this, 'create_application_password_callback' ),
			),
			'wp_delete_application_password' => array(
				'args'        => array( 'user_id', 'item' ),
				'event_type'  => Audit_Log::EVENT_TYPE_USER,
				'context'     => User_Audit::CONTEXT_PROFILE,
				'action_type' => self::ACTION_DELETED,
				'callback'    => array( $this, 'delete_application_password_callback' ),
			),
		);
	}

	/**
	 * Callback for logging application password creation.
	 * Detects if someone is creating a password for another user.
	 *
	 * @param string $hook_name The name of the hook.
	 * @param array  $params The parameters passed to the hook.
	 *
	 * @return bool|array
	 */
	public function create_application_password_callback( string $hook_name, array $params ): bool|array {
		$user_id         = $params['user_id'];
		$current_user_id = get_current_user_id();
		$blog_name       = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : '';
		$user            = get_user_by( 'id', $user_id );

		if ( ! $user ) {
			return false;
		}

		$username      = $user->user_login;
		$password_name = $params['new_item']['name'] ?? '';

		// Check if someone is creating a password for another user.
		if ( $current_user_id && $current_user_id !== $user_id ) {
			$current_user_display = $this->get_user_display( $current_user_id );

			return array(
				sprintf(
				/* translators: 1: Blog name, 2: Current user's display name, 3: Affected username, 4: Application password name. */
					esc_html__( '%1$s %2$s created an application password %4$s for %3$s', 'defender-security' ),
					$blog_name,
					$current_user_display,
					$username,
					$password_name
				),
				self::ACTION_CREATED,
			);
		}

		// User is creating their own password.
		return array(
			sprintf(
			/* translators: 1: Blog name, 2: Username, 3: Application password name. */
				esc_html__( '%1$s %2$s created an application password %3$s', 'defender-security' ),
				$blog_name,
				$username,
				$password_name
			),
			self::ACTION_CREATED,
		);
	}

	/**
	 * Callback for logging application password deletion.
	 * Detects if all passwords are being deleted at once and logs accordingly.
	 *
	 * @param string $hook_name The name of the hook.
	 * @param array  $params The parameters passed to the hook.
	 *
	 * @return bool|array
	 */
	public function delete_application_password_callback( string $hook_name, array $params ): bool|array {
		$user_id         = $params['user_id'];
		$current_user_id = get_current_user_id();
		$blog_name       = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : '';
		$user            = get_user_by( 'id', $user_id );

		if ( ! $user ) {
			return false;
		}

		$username      = $user->user_login;
		$password_name = $params['item']['name'] ?? '';

		// Check if this is a "delete all" operation by checking remaining passwords.
		$remaining_passwords = WP_Application_Passwords::get_user_application_passwords( $user_id );
		$is_delete_all       = is_array( $remaining_passwords ) && 0 === count( $remaining_passwords );

		// Generate a unique key for this user and request.
		$log_key = $user_id . '_' . ( defender_get_data_from_request( 'REQUEST_TIME_FLOAT', 's' ) ?? microtime( true ) );

		if ( ! isset( self::$deletion_count[ $log_key ] ) ) {
			self::$deletion_count[ $log_key ] = 0;
		}
		++ self::$deletion_count[ $log_key ];

		$remaining_passwords = WP_Application_Passwords::get_user_application_passwords( $user_id );
		// If this is a delete all operation, and we haven't logged it yet.
		if ( array() === $remaining_passwords && self::$deletion_count[ $log_key ] >= 1 ) {
			if ( isset( self::$logged_delete_all[ $log_key ] ) ) {
				return false;
			}

			self::$logged_delete_all[ $log_key ] = 1;

			// Check if someone is revoking passwords for another user.
			if ( $current_user_id && $current_user_id !== $user_id ) {
				$current_user_display = $this->get_user_display( $current_user_id );

				return array(
					sprintf(
					/* translators: 1: Blog name, 2: Current user's display name, 3: Affected username. */
						esc_html__( '%1$s %2$s revoked all application passwords for %3$s', 'defender-security' ),
						$blog_name,
						$current_user_display,
						$username
					),
					self::ACTION_DELETED,
				);
			}

			// User is revoking their own passwords.
			return array(
				sprintf(
				/* translators: 1: Blog name, 2: Username. */
					esc_html__( '%1$s %2$s revoked all application passwords', 'defender-security' ),
					$blog_name,
					$username
				),
				self::ACTION_DELETED,
			);
		}

		// If we already logged "delete all" for this request, suppress further logs.
		if ( isset( self::$logged_delete_all[ $log_key ] ) ) {
			return false;
		}

		// Otherwise, log single password deletion.
		// Check if someone is revoking a password for another user.
		if ( $current_user_id && $current_user_id !== $user_id ) {
			$current_user_display = $this->get_user_display( $current_user_id );

			return array(
				sprintf(
				/* translators: 1: Blog name, 2: Current user's display name, 3: Affected username, 4: Application password name. */
					esc_html__( '%1$s %2$s revoked an application password %4$s for %3$s', 'defender-security' ),
					$blog_name,
					$current_user_display,
					$username,
					$password_name
				),
				self::ACTION_DELETED,
			);
		}

		// User is revoking their own single password.
		return array(
			sprintf(
			/* translators: 1: Blog name, 2: Username, 3: Application password name. */
				esc_html__( '%1$s %2$s revoked an application password %3$s', 'defender-security' ),
				$blog_name,
				$username,
				$password_name
			),
			self::ACTION_DELETED,
		);
	}
}
