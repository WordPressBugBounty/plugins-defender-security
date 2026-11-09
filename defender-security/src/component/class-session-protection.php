<?php
/**
 * Handles session protection functionality within the WP Defender plugin.
 *
 * @package WP_Defender\Component
 * @since   5.2.0
 */

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Traits\IP;
use WP_Defender\Traits\User;
use WP_Defender\Model\Setting\Session_Protection as Settings;

/**
 * This class handles session protection functionality within the WP Defender plugin.
 */
class Session_Protection extends Component {
	use IP;
	use User;

	/**
	 * Key to lock the session to the browser.
	 */
	const LOCK_BROWSER = 'browser';

	/**
	 * Key to lock the session to the hostname.
	 */
	const LOCK_HOSTNAME = 'hostname';

	/**
	 * Key to lock the session to the IP address.
	 */
	const LOCK_IP_ADDRESS = 'ip_address';

	/**
	 * The name of the log file.
	 *
	 * @var string
	 */
	const LOG_FILE_NAME = 'session-protection';

	/**
	 * Transient key to show custom logout message in the login modal.
	 *
	 * @var string
	 */
	const LOGOUT_MSG_TRANSIENT_KEY = 'wpdef_session_logout_msg';

	/**
	 * The session protection settings.
	 *
	 * @var Settings|null
	 */
	protected ?Settings $settings;

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 *
	 * @return void
	 */
	public function __construct() {
		$this->settings = wd_di()->get( Settings::class );
	}

	/**
	 * Retrieve an array of default session lock properties.
	 *
	 * @return array An array of session lock properties.
	 */
	public static function session_lock_properties(): array {
		return array(
			self::LOCK_BROWSER    => esc_html__( 'Browser', 'defender-security' ),
			self::LOCK_HOSTNAME   => esc_html__( 'Hostname', 'defender-security' ),
			self::LOCK_IP_ADDRESS => esc_html__( 'IP Address', 'defender-security' ),
		);
	}

	/**
	 * Prepare details of the Session Lock property for MP event.
	 * No need to translate.
	 *
	 * @return string
	 */
	public function get_session_lock_string(): string {
		if ( ! $this->settings->has_properties() ) {
			return 'Not Set';
		}
		$checked_properties = array();
		if ( $this->settings->is_property_locked( self::LOCK_IP_ADDRESS ) ) {
			$checked_properties[] = 'IP';
		}
		if ( $this->settings->is_property_locked( self::LOCK_HOSTNAME ) ) {
			$checked_properties[] = 'Hostname';
		}
		if ( $this->settings->is_property_locked( self::LOCK_BROWSER ) ) {
			$checked_properties[] = 'Browser';
		}

		return implode( '/', $checked_properties );
	}

	/**
	 * Handles session timeout logic on init hook.
	 *
	 * Context: runs on AJAX and REST requests too, so a cookie-only session cannot skip the lock and idle checks.
	 * Context: AJAX/REST requests refresh last activity via update_last_activity() in this class; open idle tabs are logged out by assets/js/idle-session.js.
	 * Context: update_last_activity() stores time() in the user meta wpdef_last_act_{sha256 of token}; user meta is network-wide and survives object cache flushes.
	 * Context: cron and loopback requests are skipped; loopback detection is IP::request_is_from_server() in src/traits/ip.php.
	 * Context: request_is_from_server() is true only when the client IP is localhost, SERVER_ADDR, or the stored server IP and the User-Agent is "WordPress/{version}; {home_url}".
	 * Context: only requests that is_cookie_authenticated() (this class) confirms are checked; bearer-token logins (JWT, OAuth via determine_current_user) are skipped.
	 * Context: get_session_token() (this class) reads the token from the validated auth cookie, then the validated logged_in cookie.
	 *
	 * @return void
	 */
	public function handle_session_timeout() {
		if (
			! is_user_logged_in()
			|| ! $this->is_cookie_authenticated()
			|| wp_doing_cron()
			|| $this->request_is_from_server()
		) {
			return;
		}

		if ( ! $this->can_apply_session_protection() ) {
			return;
		}

		if ( $this->settings->has_properties() && ! $this->handle_session_lock() ) {
			return;
		}

		$idle_timeout  = $this->get_idle_timeout();
		$last_activity = $this->get_last_activity();

		if ( $last_activity && ( defender_get_current_time() - $last_activity > $idle_timeout ) ) {
			$this->log(
				sprintf( 'User session timed out due to inactivity during %s hours', $this->settings->idle_timeout ),
				self::LOG_FILE_NAME
			);
			$user_id = get_current_user_id();
			// Fires during session timeout.
			do_action( 'wpdef_session_timeout', $user_id );
			$this->logout( $user_id );

			return;
		}
		$this->update_last_activity();
	}

	/**
	 * Whether the current user is authenticated by a valid WordPress auth cookie.
	 *
	 * Context: wp_validate_auth_cookie() (wp-includes/pluggable.php) checks the HMAC and session token; with no scheme it reads the auth or secure_auth cookie, as core does at determine_current_user priority 10.
	 * Context: the logged_in scheme covers front-end requests; either cookie must resolve to the current user ID.
	 *
	 * @return bool
	 */
	private function is_cookie_authenticated(): bool {
		$user_id = get_current_user_id();

		return $user_id > 0
			&& ( wp_validate_auth_cookie() === $user_id || wp_validate_auth_cookie( '', 'logged_in' ) === $user_id );
	}

	/**
	 * Session token from the first cookie that passes wp_validate_auth_cookie(): auth, else logged_in.
	 *
	 * @return string
	 */
	private function get_session_token(): string {
		foreach ( array( '', 'logged_in' ) as $scheme ) {
			if ( wp_validate_auth_cookie( '', $scheme ) ) {
				return (string) ( wp_parse_auth_cookie( '', $scheme )['token'] ?? '' );
			}
		}

		return '';
	}

	/**
	 * Get the user meta key for server-side session last activity.
	 *
	 * @param int|null $user_id User ID.
	 * @param string   $token The session token.
	 *
	 * @return string|null
	 */
	private function get_session_activity_key( ?int $user_id = null, string $token = '' ): ?string {
		$user_id = $user_id ?? get_current_user_id();
		$token   = '' !== $token ? $token : $this->get_session_token();
		if ( ! $user_id || '' === $token ) {
			return null;
		}

		return 'wpdef_last_act_' . hash( 'sha256', $token );
	}

	/**
	 * Retrieves the last activity timestamp.
	 *
	 * Context: order is user meta, the pre-6.4.0 transient wpdef_last_act_{user}_{md5 16}, then the session's login time, so a flushed cache or older session is never read as idle.
	 * Context: the client cookie is never read; only server-side records count.
	 *
	 * @return int Last activity timestamp, or 1 when the request has no session.
	 */
	private function get_last_activity() {
		$key     = $this->get_session_activity_key();
		$user_id = get_current_user_id();
		if ( ! $key ) {
			return 1;
		}

		$token  = $this->get_session_token();
		$stored = get_user_meta( $user_id, $key, true );
		if ( ! is_numeric( $stored ) || (int) $stored <= 0 ) {
			$stored = get_transient( 'wpdef_last_act_' . $user_id . '_' . substr( md5( $token ), 0, 16 ) );
		}
		if ( is_numeric( $stored ) && (int) $stored > 0 ) {
			return (int) $stored;
		}

		$session = \WP_Session_Tokens::get_instance( $user_id )->get( $token );

		$login = (int) ( $session['login'] ?? 0 );

		return $login > 0 ? $login : 1;
	}

	/**
	 * Logs out the current user due to inactivity.
	 *
	 * Context: logoutUser() (assets/js/idle-session.js) posts action=wpdef_logout; Controller\Session_Protection::__construct() (src/controller/class-session-protection.php) hooks this to wp_ajax_wpdef_logout, which admin-ajax.php fires with no args, so $user_id arrives as ''.
	 * Context: null or '' runs check_ajax_referer() (wp-includes/pluggable.php), which ends with wp_die( -1, 403 ) on a bad nonce, then fires wpdef_session_timeout.
	 * Context: handle_session_timeout(), handle_session_lock(), is_ip_allowed(), is_hostname_allowed() and is_browser_allowed() (this class) pass get_current_user_id(), so no nonce is checked; they fire wpdef_session_timeout or wpdef_session_lock themselves, logged by User_Audit (src/component/audit/class-user-audit.php).
	 * Context: get_session_activity_key() (this class) takes ?int, so '' must not reach it.
	 * Context: reassess if the wp_ajax_wpdef_logout registration passes arguments.
	 *
	 * @param int|string|null $user_id User ID; null or '' for the AJAX request.
	 *
	 * @return void
	 */
	public function logout( $user_id = null ) {
		if ( '' === $user_id ) {
			$user_id = null;
		}
		if ( is_null( $user_id ) ) {
			check_ajax_referer( 'wpdef_logout' );
		}

		if ( is_user_logged_in() ) {
			// Case without $user_id may be from Ajax.
			if ( is_null( $user_id ) ) {
				$user_id = get_current_user_id();
				$this->log(
					sprintf( 'User session timed out due to inactivity during %s hours', $this->settings->idle_timeout ),
					self::LOG_FILE_NAME
				);
				// Fires during session timeout.
				do_action( 'wpdef_session_timeout', $user_id );
			}

			$key = $this->get_session_activity_key( $user_id );
			if ( $key ) {
				delete_user_meta( $user_id, $key );
			}

			// Destroy ONLY the current session; a request without a token never ends other sessions.
			$current_session_token = $this->get_session_token();
			if ( $current_session_token ) {
				\WP_Session_Tokens::get_instance( $user_id )->destroy( $current_session_token );
			}

			// Clear auth cookies and the current user so this request is no longer authenticated.
			wp_clear_auth_cookie();
			wp_set_current_user( 0 );

			// Reset last activity cookie.
			setcookie( 'wpdef_last_activity', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );

			// Set transient to show custom message in the login modal.
			set_site_transient( self::LOGOUT_MSG_TRANSIENT_KEY, 1, 30 );

			// Redirect to login page after session destruction.
			wp_safe_redirect( wp_login_url() );
			exit;
		}
	}

	/**
	 * Show custom message in the login modal when session is expired.
	 *
	 * @param \WP_Error $errors WP Error object.
	 *
	 * @return \WP_Error
	 */
	public function login_modal_message( $errors ) {
		$interim_login = defender_get_data_from_request( 'interim-login', 'g' );
		if ( ( ! is_null( $interim_login ) && '' !== $interim_login ) || 1 !== get_site_transient( self::LOGOUT_MSG_TRANSIENT_KEY ) ) {
			return $errors;
		}

		delete_site_transient( self::LOGOUT_MSG_TRANSIENT_KEY );

		if ( ! ( $errors instanceof \WP_Error ) ) {
			return $errors;
		}

		$error_keys = array( 'expired', 'expired_session' );
		foreach ( $error_keys as $key ) {
			if ( $errors->get_error_message( $key ) ) {
				$errors->remove( $key );
				$errors->add(
					$key,
					__( 'You\'ve been logged out due to inactivity. Please sign in to continue.', 'defender-security' ),
					'message'
				);

				break;
			}
		}

		return $errors;
	}

	/**
	 * Styles for the custom message in the login modal.
	 *
	 * @return void
	 */
	public function login_modal_message_styles(): void {
		if ( 1 === get_site_transient( self::LOGOUT_MSG_TRANSIENT_KEY ) ) {
			// Don't delete the transient here, it will be deleted in the login_modal_message() method.

			echo '<style>
				#login_error {
					border-left-color: #72aee6;
				}
			</style>';
		}
	}

	/**
	 * Enqueues JavaScript for client-side idle detection.
	 *
	 * @return void
	 */
	public function enqueue_idle_scripts() {
		if ( is_user_logged_in() && $this->can_apply_session_protection() ) {
			wp_enqueue_script( 'wpdef-session-idle', plugins_url( 'assets/js/idle-session.js', WP_DEFENDER_FILE ), array( 'jquery' ), DEFENDER_VERSION, true );
			wp_localize_script(
				'wpdef-session-idle',
				'wpdef_idle_params',
				array(
					'timeout'   => $this->get_idle_timeout(),
					'ajax_url'  => admin_url( 'admin-ajax.php' ),
					'login_url' => wp_login_url(),
					'nonce'     => wp_create_nonce( 'wpdef_logout' ),
					// Exclude sending Logout-callbacks if the user is logged out and the login form is displayed in the popup.
					'stop'      => false,
				)
			);
		}
	}

	/**
	 * Retrieves the idle timeout duration.
	 *
	 * @return int The idle timeout duration in seconds.
	 */
	public function get_idle_timeout() {
		/**
		 * Filter the idle timeout duration in seconds.
		 *
		 * @param int $idle_timeout The idle timeout duration in seconds.
		 *
		 * @return int The idle timeout duration in seconds.
		 */
		$idle_timeout = apply_filters( 'wpdef_idle_timeout', $this->settings->idle_timeout * HOUR_IN_SECONDS );
		return ! is_int( $idle_timeout ) ? (int) $idle_timeout : $idle_timeout;
	}

	/**
	 * Updates the last activity timestamp efficiently.
	 *
	 * @param string   $token The session token.
	 * @param int|null $user_id User ID.
	 *
	 * @return void
	 */
	public function update_last_activity( string $token = '', ?int $user_id = null ) {
		$key = $this->get_session_activity_key( $user_id, $token );
		if ( ! $key ) {
			return;
		}

		$user_id       = $user_id ?? get_current_user_id();
		$current_time  = time();
		$last_activity = get_user_meta( $user_id, $key, true );

		// Write at most once a minute; idle timeouts are hours.
		if ( is_numeric( $last_activity ) && $current_time - (int) $last_activity <= MINUTE_IN_SECONDS ) {
			return;
		}

		$cutoff = $current_time - max( Settings::MAX_IDLE_TIMEOUT_HOURS * HOUR_IN_SECONDS, $this->get_idle_timeout() );
		foreach ( get_user_meta( $user_id ) as $meta_key => $values ) {
			if ( str_starts_with( $meta_key, 'wpdef_last_act_' ) && (int) $values[0] < $cutoff ) {
				delete_user_meta( $user_id, $meta_key );
			}
		}

		update_user_meta( $user_id, $key, $current_time );
		setcookie( 'wpdef_last_activity', $current_time, time() + HOUR_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
	}

	/**
	 * Attach session information to the current user session.
	 *
	 * @param array $session Array of extra data.
	 *
	 * @return array Array of extra data.
	 */
	public function attach_session_information( $session ) {
		if ( $this->settings->is_property_locked( self::LOCK_IP_ADDRESS ) ) {
			$session['defender_ip'] = implode( '|', $this->get_user_ip() );
		}

		if ( $this->settings->is_property_locked( self::LOCK_HOSTNAME ) ) {
			$session['defender_hostname'] = defender_get_domain();
		}

		if ( $this->settings->is_property_locked( self::LOCK_BROWSER ) ) {
			$session['defender_browser'] = defender_get_user_agent();
		}

		return $session;
	}

	/**
	 * Write the enabled lock values into the current user's own session.
	 *
	 * Context: called after lock settings are saved or imported (src/controller/class-session-protection.php), so the admin who saves a lock keeps their session.
	 * Context: only the current session token is updated; other sessions created before the change still lack the fields and fail closed in handle_session_lock() (this class).
	 * Context: values come from attach_session_information() (this class), the same source used at login.
	 *
	 * @return void
	 */
	public function attach_lock_data_to_current_session(): void {
		$user_id = get_current_user_id();
		$token   = $this->get_session_token();
		if ( ! $user_id || '' === $token ) {
			return;
		}

		$manager = \WP_Session_Tokens::get_instance( $user_id );
		$session = $manager->get( $token );
		if ( ! is_array( $session ) ) {
			return;
		}

		$manager->update( $token, $this->attach_session_information( $session ) );
	}

	/**
	 * Handles session lock logic.
	 *
	 * Context: every enabled lock is checked; a missing defender_ip / defender_hostname / defender_browser field reads as '' and fails closed.
	 * Context: is_ip_allowed(), is_hostname_allowed(), is_browser_allowed() (this file) treat '' on either side as a mismatch and call logout().
	 * Context: the fields are set at login by attach_session_information() (this file), hooked in src/controller/class-session-protection.php while locks are configured.
	 * Context: session data lives in the session_tokens user meta (wp-includes/class-wp-session-tokens.php); the client cannot write it.
	 * Context: sessions created before a lock is enabled lack the field, so they are logged out on their next request.
	 * Context: reassess if the `?? ''` defaults below or the '' checks in the is_*_allowed() helpers change.
	 *
	 * @return bool True when the session remains valid, false when it is terminated.
	 */
	public function handle_session_lock() {
		$token        = $this->get_session_token();
		$user_id      = get_current_user_id();
		$manager      = \WP_Session_Tokens::get_instance( $user_id );
		$session_data = $manager->get( $token );
		if ( ! is_array( $session_data ) ) {
			$this->log( 'Session data is missing or malformed. Destroying the current session.', self::LOG_FILE_NAME );
			$this->logout( $user_id );
			return false;
		}
		$user_ips = $this->get_user_ip();
		// Work with the Session Lock options.
		if ( $this->settings->is_property_locked( self::LOCK_IP_ADDRESS ) ) {
			$ips = implode( '|', $user_ips );
			if ( ! $this->is_ip_allowed( $ips, $session_data['defender_ip'] ?? '', $user_id ) ) {
				return false;
			}
		}

		if ( $this->settings->is_property_locked( self::LOCK_HOSTNAME ) ) {
			$hostname = defender_get_domain();
			if ( ! $this->is_hostname_allowed( $hostname, $session_data['defender_hostname'] ?? '', $user_id ) ) {
				return false;
			}
		}

		if ( $this->settings->is_property_locked( self::LOCK_BROWSER ) ) {
			$browser = defender_get_user_agent();
			if ( ! $this->is_browser_allowed( $browser, $session_data['defender_browser'] ?? '', $user_id ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Verifies if the given IP is allowed based on the session information.
	 *
	 * @param string $ip IP addresses to check.
	 * @param string $session_ip Session IP address.
	 * @param int    $user_id User ID.
	 *
	 * @return bool True when the IP is allowed, false when the session is terminated.
	 */
	private function is_ip_allowed( $ip, $session_ip, $user_id ) {
		if ( '' === $ip || '' === $session_ip || $ip !== $session_ip ) {
			$this->log(
				sprintf(
					'IP address mismatch detected. Detected: %s, Expected: %s.',
					$ip,
					$session_ip
				),
				self::LOG_FILE_NAME
			);
			/**
			 * Fires during session lock.
			 *
			 * @param int    $user_id
			 * @param string $session_lock_type
			 */
			do_action( 'wpdef_session_lock', $user_id, 'IP address' );
			$this->logout( $user_id );

			return false;
		}

		return true;
	}

	/**
	 * Verifies if the given hostname is allowed based on the session information.
	 *
	 * @param string $hostname Hostname to check.
	 * @param string $session_hostname Session hostname.
	 * @param int    $user_id User ID.
	 *
	 * @return bool True when the hostname is allowed, false when the session is terminated.
	 */
	private function is_hostname_allowed( $hostname, $session_hostname, $user_id ) {
		if ( '' === $hostname || '' === $session_hostname || strcasecmp( $hostname, $session_hostname ) !== 0 ) {
			$this->log(
				sprintf(
					'Hostname mismatch detected. Detected: %s, Expected: %s.',
					$hostname,
					$session_hostname
				),
				self::LOG_FILE_NAME
			);
			do_action( 'wpdef_session_lock', $user_id, 'hostname' );
			$this->logout( $user_id );

			return false;
		}

		return true;
	}

	/**
	 * Verifies if the given browser is allowed based on the session information.
	 *
	 * @param string $browser Browser to check.
	 * @param string $session_browser Session browser.
	 * @param int    $user_id User ID.
	 *
	 * @return bool True when the browser is allowed, false when the session is terminated.
	 */
	private function is_browser_allowed( $browser, $session_browser, $user_id ) {
		if ( '' === $browser || '' === $session_browser || strcasecmp( $browser, $session_browser ) !== 0 ) {
			$this->log(
				sprintf(
					'Browser mismatch detected. Detected: %s, Expected: %s.',
					$browser,
					$session_browser
				),
				self::LOG_FILE_NAME
			);
			do_action( 'wpdef_session_lock', $user_id, 'browser' );
			$this->logout( $user_id );

			return false;
		}

		return true;
	}

	/**
	 * Should we apply this feature for the current user?
	 *
	 * @return bool
	 */
	public function can_apply_session_protection(): bool {
		$current_user = $this->get_user( get_current_user_id() );

		/**
		 * Filter whether to apply the feature for the current user.
		 *
		 * @param bool     $apply         Whether to apply the feature.
		 * @param \WP_User $current_user  The current user object.
		 *
		 * @return bool
		 */
		$protection = apply_filters( 'wpdef_toggle_session_protection', $this->should_enforce_for_user( $current_user, $this->settings ), $current_user );

		return is_bool( $protection ) ? $protection : (bool) $protection;
	}
}
