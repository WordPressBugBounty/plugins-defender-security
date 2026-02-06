<?php
/**
 * Handles user-related audit events.
 *
 * @package WP_Defender\Component\Audit
 */

namespace WP_Defender\Component\Audit;

use WP_User;
use WP_Error;
use stdClass;
use WP_Defender\Traits\User;
use WP_Defender\Model\Audit_Log;

/**
 * Handle user-related audit events such as login, logout, registration, and profile updates.
 */
class User_Audit extends Audit_Event {

	use User;

	public const ACTION_LOGIN = 'login', ACTION_LOGOUT = 'logout', ACTION_REGISTERED = 'registered',
		ACTION_LOST_PASS      = 'lost_password', ACTION_RESET_PASS = 'reset_password',
		ACTION_CREATED        = 'created', ACTION_ADDED = 'added',
		ACTION_GRANTED        = 'granted', ACTION_REVOKED = 'revoked';

	public const CONTEXT_SESSION = 'session', CONTEXT_USERS = 'users', CONTEXT_PROFILE = 'profile',
		CONTEXT_MULTISITE_USERS  = 'multisite_users', CONTEXT_SUPER_ADMIN = 'super-admin';

	/**
	 * Cached old user data used for tracking changes to user profiles.
	 *
	 * This array stores old user data when a user's profile is updated.
	 * The data is keyed by user ID and contains the user's metadata before the update.
	 *
	 * @var array
	 */
	private static array $cached_old_user_data = array();

	/**
	 * Returns an array of hooks associated with various user actions to capture and log them.
	 *
	 * @return array
	 */
	public function get_hooks(): array {

		$hooks = array(
			'user_profile_update_errors'   => array(
				'args'     => array( 'errors', 'update', 'user' ),
				'callback' => array( $this, 'cache_old_user_data' ),
			),
			'wp_login_failed'              => array(
				'args'        => array( 'username' ),
				'text'        => sprintf(
				/* translators: 1: Blog name, 2: Username */
					esc_html__( '%1$s User login fail. Username: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{username}}'
				),
				'event_type'  => Audit_Log::EVENT_TYPE_USER,
				'context'     => self::CONTEXT_SESSION,
				'action_type' => self::ACTION_LOGIN,
			),
			'wp_login'                     => array(
				'args'        => array( 'userlogin', 'user' ),
				'text'        => sprintf(
				/* translators: 1: Blog name, 2: Username */
					esc_html__( '%1$s User login success: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{userlogin}}'
				),
				'event_type'  => Audit_Log::EVENT_TYPE_USER,
				'context'     => self::CONTEXT_SESSION,
				'action_type' => self::ACTION_LOGIN,
			),
			'wpmu_2fa_login'               => array(
				'args'         => array( 'user_id', '2fa_slug' ),
				'text'         => sprintf(
				/* translators: 1: Blog name, 2: 2fa method slug, 3: Username. */
					esc_html__( '%1$s 2fa with %2$s method login success for user: %3$s', 'defender-security' ),
					'{{blog_name}}',
					'{{2fa_slug}}',
					'{{username}}'
				),
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'context'      => self::CONTEXT_SESSION,
				'action_type'  => self::ACTION_LOGIN,
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array(
							'id',
							'{{user_id}}',
						),
						'result_property' => 'user_login',
					),
				),
			),
			'wp_logout'                    => array(
				'args'         => array( 'user_id' ),
				'text'         => sprintf(
				/* translators: 1: Blog name, 2: Username */
					esc_html__( '%1$s User logout success: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{username}}'
				),
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'action_type'  => self::ACTION_LOGOUT,
				'context'      => self::CONTEXT_SESSION,
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array(
							'id',
							'{{user_id}}',
						),
						'result_property' => 'user_login',
					),
				),
			),
			'user_register'                => array(
				'args'        => array( 'user_id' ),
				'event_type'  => Audit_Log::EVENT_TYPE_USER,
				'context'     => self::CONTEXT_USERS,
				'action_type' => self::ACTION_REGISTERED,
				'callback'    => array( $this, 'created_new_user_callback' ),
			),
			'delete_user'                  => array(
				'args'         => array( 'user_id' ),
				'text'         => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: User ID, 4: Username */
					esc_html__( '%1$s %2$s deleted a user: ID: %3$s, username: %4$s', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{user_id}}',
					'{{username}}'
				),
				'context'      => self::CONTEXT_USERS,
				'action_type'  => self::ACTION_DELETED,
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array(
							'id',
							'{{user_id}}',
						),
						'result_property' => 'user_login',
					),
				),
			),
			'remove_user_from_blog'        => array(
				'args'        => array( 'user_id', 'blog_id' ),
				'context'     => self::CONTEXT_USERS,
				'action_type' => self::ACTION_DELETED,
				'event_type'  => Audit_Log::EVENT_TYPE_USER,
				'callback'    => array( self::class, 'remove_user_from_blog_callback' ),
			),
			'wpmu_delete_user'             => array(
				'args'         => array( 'user_id' ),
				'text'         => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: User ID, 4: Username */
					esc_html__( '%1$s %2$s deleted a user: ID: %3$s, username: %4$s', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{user_id}}',
					'{{username}}'
				),
				'context'      => self::CONTEXT_USERS,
				'action_type'  => self::ACTION_DELETED,
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array(
							'id',
							'{{user_id}}',
						),
						'result_property' => 'user_login',
					),
				),
			),
			'profile_update'               => array(
				'args'        => array( 'user_id', 'old_user_data', 'userdata' ),
				'action_type' => self::ACTION_UPDATED,
				'event_type'  => Audit_Log::EVENT_TYPE_USER,
				'context'     => self::CONTEXT_PROFILE,
				'callback'    => array( self::class, 'profile_update_callback' ),
			),
			'retrieve_password'            => array(
				'args'         => array( 'username' ),
				'text'         => sprintf(
				/* translators: 1: Blog name, 2: Username */
					esc_html__( '%1$s Password requested to reset for user: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{username}}'
				),
				'action_type'  => self::ACTION_LOST_PASS,
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'context'      => self::CONTEXT_PROFILE,
				'program_args' => array(
					'user' => array(
						'callable' => 'get_user_by',
						'params'   => array(
							'login',
							'{{username}}',
						),
					),
				),
			),
			'after_password_reset'         => array(
				'args'        => array( 'user' ),
				'text'        => sprintf(
				/* translators: 1: Blog name, 2: Username. */
					esc_html__( '%1$s Password reset for user: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{user_login}}'
				),
				'event_type'  => Audit_Log::EVENT_TYPE_USER,
				'action_type' => self::ACTION_RESET_PASS,
				'context'     => self::CONTEXT_PROFILE,
				'custom_args' => array(
					'user_login' => '{{user->user_login}}',
				),
			),
			'set_user_role'                => array(
				'args'         => array( 'user_ID', 'new_role', 'old_role' ),
				'text'         => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Username, 4: Old user role, 5: New user role */
					esc_html__( "%1\$s %2\$s changed user %3\$s's role from %4\$s to %5\$s", 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{username}}',
					'{{from_role}}',
					'{{new_role}}'
				),
				'action_type'  => self::ACTION_UPDATED,
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'context'      => self::CONTEXT_PROFILE,
				'custom_args'  => array(
					'from_role' => '{{old_role->0}}',
				),
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array(
							'id',
							'{{user_ID}}',
						),
						'result_property' => 'user_login',
					),
				),
				'false_when'   => array(
					array(
						'{{old_role}}',
						array(),
						'==',
					),
				),
			),
			'wpdef_session_lock'           => array(
				'args'         => array( 'user_id', 'session_lock_type' ),
				'text'         => sprintf(
					/* translators: 1: Blog name, 2: Username, 3: Session lock type. */
					esc_html__( '%1$s User session ended for %2$s due to a change in %3$s', 'defender-security' ),
					'{{blog_name}}',
					'{{username}}',
					'{{session_lock_type}}'
				),
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'context'      => self::CONTEXT_SESSION,
				'action_type'  => self::ACTION_LOGIN,
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array(
							'id',
							'{{user_id}}',
						),
						'result_property' => 'user_login',
					),
				),
			),
			'wpdef_session_timeout'        => array(
				'args'         => array( 'user_id' ),
				'text'         => sprintf(
					/* translators: 1: Blog name, 2: Username. */
					esc_html__( '%1$s User session ended for %2$s due to an idle session', 'defender-security' ),
					'{{blog_name}}',
					'{{username}}'
				),
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'context'      => self::CONTEXT_SESSION,
				'action_type'  => self::ACTION_LOGIN,
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array(
							'id',
							'{{user_id}}',
						),
						'result_property' => 'user_login',
					),
				),
			),
			// Since 5.6.0.
			'wpmudev_sso_set_current_user' => array(
				'args'         => array( 'user_id' ),
				'text'         => sprintf(
				/* translators: 1: Blog name, 2: Username. */
					esc_html__( '%1$s Hub SSO login success: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{username}}'
				),
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'context'      => self::CONTEXT_SESSION,
				'action_type'  => self::ACTION_LOGIN,
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array(
							'id',
							'{{user_id}}',
						),
						'result_property' => 'user_login',
					),
				),
			),
		);

		if ( is_multisite() ) {
			$hooks['granted_super_admin'] = array(
				'args'         => array( 'user_id' ),
				'text'         => sprintf(
				/* translators: 1: Blog name. 2: Actor username. 3: Affected username. */
					esc_html__( '%1$s %2$s granted Super Admin privileges to %3$s', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{username}}'
				),
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'context'      => self::CONTEXT_SUPER_ADMIN,
				'action_type'  => self::ACTION_GRANTED,
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array( 'id', '{{user_id}}' ),
						'result_property' => 'user_login',
					),
				),
			);
			$hooks['revoked_super_admin'] = array(
				'args'         => array( 'user_id' ),
				'text'         => sprintf(
				/* translators: 1: Blog name. 2: Actor username. 3: Affected username. */
					esc_html__( '%1$s %2$s revoked Super Admin privileges from %3$s', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{username}}'
				),
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'context'      => self::CONTEXT_SUPER_ADMIN,
				'action_type'  => self::ACTION_REVOKED,
				'program_args' => array(
					'username' => array(
						'callable'        => 'get_user_by',
						'params'          => array( 'id', '{{user_id}}' ),
						'result_property' => 'user_login',
					),
				),
			);
			$hooks['wpmu_new_user']    = array(
				'args'        => array( 'user_id' ),
				'event_type'  => Audit_Log::EVENT_TYPE_USER,
				'context'     => self::CONTEXT_MULTISITE_USERS,
				'action_type' => self::ACTION_CREATED,
				'callback'    => array( $this, 'created_new_user_callback' ),
			);
			$hooks['add_user_to_blog'] = array(
				'args'         => array( 'user_id', 'role', 'blog_id' ),
				'text'         => sprintf(
					/* translators: 1: Blog name, 2: Username, 3: User role. */
					esc_html__( 'User added to %1$s, Username: %2$s, Role: %3$s', 'defender-security' ),
					'{{site_name}}',
					'{{username}}',
					'{{role}}'
				),
				'event_type'   => Audit_Log::EVENT_TYPE_USER,
				'context'      => self::CONTEXT_MULTISITE_USERS,
				'action_type'  => self::ACTION_ADDED,
				'program_args' => array(
					'site_name' => array(
						'callable'        => 'get_blog_details',
						'params'          => array( '{{blog_id}}' ),
						'result_property' => 'blogname',
					),
					'username'  => array(
						'callable'        => 'get_user_by',
						'params'          => array( 'id', '{{user_id}}' ),
						'result_property' => 'user_login',
					),
				),
			);
		}

		return $hooks;
	}

	/**
	 * Log when user is created on MU.
	 *
	 * @param int $user_id User ID.
	 *
	 * @return bool|array
	 */
	public function created_new_user_callback( int $user_id ): bool|array {
		$user          = get_user_by( 'id', $user_id );
		$username      = $user->user_login ?? '';
		$blog_name     = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : 'the site';
		$userdata_role = defender_get_data_from_request( 'role', 'p' );

		if ( ! isset( $user->roles[0], $userdata_role ) || $userdata_role !== $user->roles[0] ) {
			return false;
		}
		$role   = $this->get_first_user_role( $user );
		$action = defender_get_data_from_request( 'action', 'p' );
		if ( is_admin() ) {
			return array(
				sprintf(
				/* translators: 1: Blog name, 2: Username, 3: User role. */
					esc_html__( 'User %1$s %2$s, Username: %3$s, Role: %4$s', 'defender-security' ),
					'created' === $action ? 'created on' : 'added to',
					$blog_name,
					$username,
					$role
				),
				self::ACTION_CREATED,
			);
		} else {
			return array(
				sprintf(
								/* translators: 1: Blog name, 2: Username, 3: User role */
					esc_html__( '%1$s A new user registered: Username: %2$s, Role: %3$s', 'defender-security' ),
					$blog_name,
					$username,
					$role
				),
			);
		}
	}

	/**
	 * Log when user is removed from a blog.
	 *
	 * @return bool|array
	 */
	public function remove_user_from_blog_callback() {
		$action = defender_get_data_from_request( 'action', 'p' );
		if ( 'doremove' !== $action ) {
			return false;
		}

		$args                 = func_get_args();
		$user_id              = $args[1]['user_id'];
		$blog_id              = $args[1]['blog_id'];
		$user                 = get_user_by( 'id', $user_id );
		$username             = $user->user_login ?? '';
		$current_user_display = $this->get_user_display( get_current_user_id() );
		$blog_name            = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : '';

		return array(
			sprintf(
			/* translators: 1: Blog name, 2: User's display name, 3: User ID, 4: Username, 5: Blog ID */
				esc_html__( '%1$s %2$s removed a user: ID: %3$s, username: %4$s from blog %5$s', 'defender-security' ),
				$blog_name,
				$current_user_display,
				$user_id,
				$username,
				$blog_id
			),
			self::ACTION_DELETED,
		);
	}

	/**
	 * Callback for logging when a user's profile is updated. It distinguishes between self-updates and updates made by
	 * other users.
	 *
	 * @param int     $user_id       User ID.
	 * @param WP_User $old_user_data Object containing user's data prior to update.
	 * @param array   $userdata      The raw array of data passed to wp_insert_user().
	 *
	 * @return bool|array
	 */
	public function profile_update_callback( int $user_id, WP_User $old_user_data, array $userdata ): bool|array {
		$from = defender_get_data_from_request( 'from', 'p' );
		if ( 'profile' !== $from ) {
			return false;
		}
		$diff_assoc = array_diff_assoc( $userdata, self::$cached_old_user_data[ $user_id ] ?? array() );
		if ( array() === $diff_assoc ) {
			return false;
		}
		$current_user = get_user_by( 'id', $user_id );
		if ( array_key_exists( 'user_pass', $diff_assoc ) && $old_user_data->user_pass !== $userdata['user_pass'] ) {
			$password_audit = new Password_Audit();
			return $password_audit->build_log( $current_user );
		}
		$blog_name       = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : '';
		$current_user_id = get_current_user_id();

		if ( $current_user_id === $user_id ) {

			return array(
				sprintf(
				/* translators: 1: Blog name, 2: User's nicename */
					esc_html__( '%1$s User %2$s updated his/her profile', 'defender-security' ),
					$blog_name,
					$current_user->user_nicename
				),
				self::ACTION_UPDATED,
			);
		} elseif ( 0 !== $current_user_id ) {

			return array(
				sprintf(
				/* translators: 1: Blog name, 2: User's display name, 3: User's nicename */
					esc_html__( "%1\$s %2\$s updated user %3\$s's profile information", 'defender-security' ),
					$blog_name,
					$this->get_user_display( $current_user_id ),
					$current_user->user_nicename
				),
				self::ACTION_UPDATED,
			);
		}

		return false;
	}

	/**
	 * Provides a dictionary for translating action constants into human-readable strings.
	 *
	 * @return array
	 */
	public function dictionary(): array {
		return array(
			self::ACTION_LOST_PASS  => esc_html__( 'lost password', 'defender-security' ),
			self::ACTION_REGISTERED => esc_html__( 'registered', 'defender-security' ),
			self::ACTION_LOGIN      => esc_html__( 'login', 'defender-security' ),
			self::ACTION_LOGOUT     => esc_html__( 'logout', 'defender-security' ),
			self::ACTION_RESET_PASS => esc_html__( 'password reset', 'defender-security' ),
			self::ACTION_CREATED    => esc_html__( 'created', 'defender-security' ),
			self::ACTION_ADDED      => esc_html__( 'added', 'defender-security' ),
			self::ACTION_GRANTED    => esc_html__( 'granted', 'defender-security' ),
			self::ACTION_REVOKED    => esc_html__( 'revoked', 'defender-security' ),
		);
	}

	/**
	 * Static method to retrieve the role of a user by their ID
	 *
	 * @param  int $user_id  The ID of the user whose role is to be fetched.
	 *
	 * @return string
	 */
	public static function get_user_role( $user_id ): string {
		$user = get_user_by( 'id', $user_id );
		if ( $user instanceof WP_User ) {
			$_this = new self();

			return $_this->get_first_user_role( $user );
		} else {
			return '';
		}
	}

	/**
	 * Check if it is a create new user request.
	 *
	 * @since 2.8.0
	 * @return bool
	 */
	public static function is_create_user_action(): bool {
		$action = defender_get_data_from_request( 'action', 'p' );
		if ( 'createuser' === $action ) {
			return true;
		}

		return false;
	}

	/**
	 * Cache old user data from when a user's profile is updated.
	 *
	 * @param WP_Error $errors WP_Error object (passed by reference).
	 * @param bool     $update Whether this is a user update.
	 * @param stdClass $user   User object (passed by reference).
	 *
	 * @return WP_Error The errors that occurred during the action.
	 */
	public function cache_old_user_data( WP_Error $errors, bool $update, stdClass $user ): WP_Error {
		if ( $update ) {
			$id           = $user->ID;
			$current_user = get_userdata( $id );
			$user_array   = $current_user->to_array();
			$meta         = array(
				'first_name'           => get_user_meta( $current_user->ID, 'first_name', true ),
				'last_name'            => get_user_meta( $current_user->ID, 'last_name', true ),
				'nickname'             => get_user_meta( $current_user->ID, 'nickname', true ),
				'description'          => get_user_meta( $current_user->ID, 'description', true ),
				'rich_editing'         => get_user_meta( $current_user->ID, 'rich_editing', true ),
				'syntax_highlighting'  => get_user_meta( $current_user->ID, 'syntax_highlighting', true ),
				'comment_shortcuts'    => get_user_meta( $current_user->ID, 'comment_shortcuts', true ) === 'true' ? 'true' : '',
				'locale'               => get_user_meta( $current_user->ID, 'locale', true ),
				'admin_color'          => get_user_meta( $current_user->ID, 'admin_color', true ),
				'use_ssl'              => get_user_meta( $current_user->ID, 'use_ssl', true ),
				'show_admin_bar_front' => get_user_meta( $current_user->ID, 'show_admin_bar_front', true ),
			);

			self::$cached_old_user_data[ $id ] = array_merge_recursive( $user_array, $meta );
		}

		return $errors;
	}
}
