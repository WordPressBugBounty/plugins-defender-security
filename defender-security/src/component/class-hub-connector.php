<?php
/**
 * Hub Connector class.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WPMUDEV\Hub\Connector;
use Calotes\Base\Component;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Traits\Defender_Dashboard_Client;
use WPMUDEV\Hub\Connector\API;

/**
 * Handles the functionality related to the Hub Connector module.
 *
 * @since 4.10.0
 */
class Hub_Connector extends Component {
	use Defender_Dashboard_Client;

	/**
	 * The identifier for the WP Defender plugin in the Hub.
	 *
	 * @const string
	 */
	public const PLUGIN_IDENTIFIER = 'defender';

	/**
	 * The action name used for the Hub connection.
	 *
	 * @const string
	 */
	public const CONNECTION_ACTION = 'hub_connection';

	/**
	 * Temporary flag used while the first Hub sync is being checked.
	 *
	 * @const string
	 */
	public const SYNCING_TRANSIENT_KEY = 'wpdef_hc_site_syncing';

	/**
	 * Checks if the Hub connector should render its UI.
	 *
	 * Verifies the nonce from the global-ip page to determine if the Hub connector should render its UI.
	 *
	 * @return bool The nonce value on success, false on failure.
	 */
	public static function should_render() {
		// Team selection callbacks need the library's own UI — let them through.
		if ( self::is_team_selection_callback() ) {
			return ! self::get_hcm_status() && wp_verify_nonce( defender_get_data_from_request( '_def_nonce', 'g' ), self::CONNECTION_ACTION );
		}

		$page_action     = sanitize_text_field( wp_unslash( $_GET['page_action'] ?? '' ) );
		$is_hub_callback = ! empty( $_GET['hub_connector_callback'] );

		if ( self::CONNECTION_ACTION === $page_action || $is_hub_callback ) {
			return false;
		}

		return ! self::get_hcm_status() && wp_verify_nonce( defender_get_data_from_request( '_def_nonce', 'g' ), self::CONNECTION_ACTION );
	}

	/**
	 * Initialize the Hub Connector module and set its options.
	 *
	 * The `extra/hub-connector/connector.php` file is required, and the options are set for the Hub Connector module.
	 *
	 * @return void
	 */
	public function init() {
		require_once defender_path( 'extra/hub-connector/connector.php' );
		$options = array(
			'screens'    => array(
				'toplevel_page_wp-defender',
				'toplevel_page_wp-defender-network',
				'defender_page_wdf-ip-lockout',
				'defender_page_wdf-ip-lockout-network',
				'defender-pro_page_wdf-ip-lockout',
				'defender-pro_page_wdf-ip-lockout-network',
			),
			'extra_args' => array(
				'register' => array(
					'connect_ref' => self::PLUGIN_IDENTIFIER,
					'utm_medium'  => 'plugin',
					'utm_source'  => self::PLUGIN_IDENTIFIER,
				),
			),
		);
		// Get advanced params.
		$page = defender_get_data_from_request( 'page', 'g' );
		$view = defender_get_data_from_request( 'view', 'g' );

		$result = $this->maybe_summary_box_trigger( $view );
		// Get advanced params.
		$res = $this->get_utm_tags( $page, $result['view'], $result['is_summary'] );
		if ( '' !== $res['utm_campaign'] ) {
			$options['extra_args']['register']['utm_campaign'] = $res['utm_campaign'];
		}
		if ( '' !== $res['utm_content'] ) {
			$options['extra_args']['register']['utm_content'] = $res['utm_content'];
		}

		Connector::get()->set_options( self::PLUGIN_IDENTIFIER, $options );
	}

	/**
	 * Checks if the current request is a Hub team-selection callback.
	 *
	 * @return bool
	 */
	public static function is_team_selection_callback(): bool {
		return ! empty( $_REQUEST['hub_connector_callback'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			&& ! empty( $_REQUEST['user_apikey'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			&& 1 === (int) ( $_REQUEST['is_multi_auth'] ?? 0 ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}

	/**
	 * Gets the label for the button to connect the site to the Hub.
	 *
	 * @return string The label for the button.
	 */
	public function get_button_label(): string {
		if ( $this->is_dash_installed() && ! $this->is_dash_activated() ) {
			return __( 'Activate WPMU DEV Dashboard', 'defender-security' );
		}
		if ( $this->is_dash_activated() ) {
			return __( 'Log in to WPMU DEV', 'defender-security' );
		}
		return __( 'Connect site for Full protection', 'defender-security' );
	}

	/**
	 * Modify text string vars.
	 *
	 * @param array  $texts  Vars.
	 * @param string $plugin Plugin identifier.
	 *
	 * @return array
	 */
	public static function customize_text_vars( $texts, $plugin ): array {
		if ( self::PLUGIN_IDENTIFIER === $plugin ) {
			$feature_name                 = self::get_feature_name();
			$texts['create_account_desc'] = sprintf(
				/* translators: 1. Feature name. 2. Opened tag. 3. Closed tag. */
				esc_html__( 'Create a free account to connect your site to WPMU DEV and activate %1$s. %2$sIt`s fast, seamless, and free%3$s.', 'defender-security' ),
				'<strong>' . __( 'Defender - ', 'defender-security' ) . $feature_name . '</strong>',
				'<i>',
				'</i>'
			);
			$texts['login_desc'] = sprintf(
				/* translators: %s: Feature name. */
				esc_html__( 'Log in with your WPMU DEV account credentials to activate %s.', 'defender-security' ),
				$feature_name
			);
		}

		return $texts;
	}

	/**
	 * Get feature's name.
	 *
	 * @return string
	 */
	public static function get_feature_name(): string {
		$feature_name = defender_get_data_from_request( 'module_name', 'g' );
		if ( ! is_null( $feature_name ) && '' !== $feature_name ) {
			return $feature_name;
		}

		$view = defender_get_data_from_request( 'view', 'g' );
		switch ( $view ) {
			case 'blocklist':
				return __( 'Custom IP Allow/Block list', 'defender-security' );
			default:
				return __( 'AntiBot Global Firewall', 'defender-security' );
		}
	}

	/**
	 * Get UTM tags.
	 *
	 * @param string $page The page to load.
	 * @param string $view The view to load.
	 * @param bool   $is_summary Is this from the Summary section? Default false.
	 *
	 * @return array
	 */
	private function get_utm_tags( string $page = '', string $view = '', bool $is_summary = false ): array {
		$utm_campaign = '';
		$utm_content  = '';
		if ( '' !== $page ) {
			switch ( $page ) {
				// There are buttons on notice or widget on the Dashboard page.
				case 'wp-defender':
					$utm_content  = 'hub-connector';
					$utm_campaign = ( 'dashboard' === $view )
						? 'defender_dashboard_firewall_antibot'
						: 'defender_onboarding_antibot';
					break;
				case 'wdf-ip-lockout':
					$utm_content = 'hub-connector';
					if ( $is_summary ) {
						$utm_campaign = 'defender_firewall_antibot_summary';
					} else {
						$utm_campaign = ( 'blocklist' === $view )
							? 'defender_firewall_centralip'
							: 'defender_firewall_antibot';
					}
					break;
				default:
					break;
			}
		}

		return array(
			'utm_campaign' => $utm_campaign,
			'utm_content'  => $utm_content,
		);
	}

	/**
	 * Update data if a trigger is the Summary section.
	 *
	 * @param string $view The view to load.
	 *
	 * @return array
	 */
	private function maybe_summary_box_trigger( string $view ): array {
		return array(
			'view'       => 'summary-box' === $view ? 'global-ip' : $view,
			'is_summary' => 'summary-box' === $view,
		);
	}

	/**
	 * Retrieve the Hub connector URL.
	 *
	 * @param string $page Optional. The page to load. Default is empty string.
	 * @param string $view Optional. The view to load. Default is empty string.
	 * @param string $utm_campaign Optional. The UTM campaign parameter. Default is empty string.
	 * @param string $utm_content Optional. The UTM content parameter. Default is empty string.
	 * @param string $module_slug Optional. Module slug for post-connection auto-enable. Default is empty string.
	 *
	 * @return string
	 */
	public function get_url( string $page = '', string $view = '', string $utm_campaign = '', string $utm_content = '', string $module_slug = '' ): string {
		$args = self::get_connection_args( '' !== $page ? $page : 'wp-defender', $module_slug );

		if ( '' !== $view ) {
			$args['view'] = $view;
		}

		$result = $this->maybe_summary_box_trigger( $view );
		// Get advanced params.
		$res = $this->get_utm_tags( $page, $result['view'], $result['is_summary'] );

		if ( '' !== $utm_campaign ) {
			$args['utm_campaign'] = $utm_campaign;
		} elseif ( '' !== $res['utm_campaign'] ) {
			$args['utm_campaign'] = $res['utm_campaign'];
		}

		if ( '' !== $utm_content ) {
			$args['utm_content'] = $utm_content;
		} elseif ( '' !== $res['utm_content'] ) {
			$args['utm_content'] = $res['utm_content'];
		}

		return add_query_arg( $args, self::get_admin_url() );
	}

	/**
	 * Checks if Hub Connector is logged in.
	 *
	 * @return bool
	 */
	public static function is_logged_in(): bool {
		if ( ! class_exists( '\WPMUDEV\Hub\Connector\API' ) ) {
			return false;
		}

		$api = API::get();

		return $api && method_exists( $api, 'is_logged_in' ) && $api->is_logged_in();
	}

	/**
	 * Sync site data with Hub.
	 *
	 * @return bool|\WP_Error
	 */
	public function sync() {
		if ( ! class_exists( '\WPMUDEV\Hub\Connector\API' ) ) {
			return false;
		}

		$api = API::get();

		if ( $api && method_exists( $api, 'sync_site' ) ) {
			$sync = $api->sync_site();
			if ( is_wp_error( $sync ) ) {
				return $sync;
			}
		}

		return true;
	}

	/**
	 * Verify the auth nonce from request.
	 *
	 * @return bool
	 */
	public static function verify_auth_nonce(): bool {
		return (bool) wp_verify_nonce(
			sanitize_text_field( wp_unslash( $_REQUEST['auth_nonce'] ?? '' ) ),
			'auth_nonce'
		);
	}

	/**
	 * Check if the site is in the temporary post-auth Hub syncing state.
	 *
	 * @return bool
	 */
	public static function is_syncing(): bool {
		// If already logged in or a login error occurred, the auth flow is settled —
		// clear any stale syncing transient and report not syncing.
		if ( self::is_logged_in() || self::has_error_in_login() ) {
			delete_site_transient( self::SYNCING_TRANSIENT_KEY );

			return false;
		}

		$page_action = sanitize_text_field( wp_unslash( $_REQUEST['page_action'] ?? '' ) );
		$syncing     = current_user_can( 'manage_options' )
			&& self::verify_auth_nonce()
			&& self::CONNECTION_ACTION === $page_action
			&& ! empty( $_REQUEST['set_apikey'] );

		if ( $syncing ) {
			set_site_transient( self::SYNCING_TRANSIENT_KEY, true, MINUTE_IN_SECONDS );
		}

		return (bool) get_site_transient( self::SYNCING_TRANSIENT_KEY );
	}

	/**
	 * Check if there is an error in login response from HUB.
	 *
	 * @return bool
	 */
	public static function has_error_in_login() {
		$page_action     = sanitize_text_field( wp_unslash( $_GET['page_action'] ?? '' ) );
		$api_error       = sanitize_text_field( wp_unslash( $_GET['api_error'] ?? 0 ) );
		$is_hub_callback = ! empty( $_GET['hub_connector_callback'] );

		if ( self::CONNECTION_ACTION === $page_action ) {
			return ! empty( $api_error );
		}

		if ( ! $is_hub_callback || ! self::verify_auth_nonce() ) {
			return false;
		}

		return ! empty( $api_error );
	}

	/**
	 * Get authentication error messages. Copied from HC.
	 *
	 * Based on the error code, prepare different error messages.
	 *
	 * @return string
	 */
	public static function get_auth_error(): string {
		/**
		 * Nonce is verified in `process_auth_callback` before this method called.
		 *
		 * @see self::process_auth_callback()
		 */
		// phpcs:disable WordPress.Security.NonceVerification.Recommended

		$error               = '';
		$reset_url           = class_exists( '\WPMUDEV\Hub\Connector\Data' )
			? \WPMUDEV\Hub\Connector\Data::get()->server_url( 'forgot-password' )
			: 'https://wpmudev.com/forgot-password';
		$skip_trial_url      = \WPMUDEV\Hub\Connector\Data::get()->server_url( 'hub/account/?skip_trial' );
		$trial_info_url      = \WPMUDEV\Hub\Connector\Data::get()->server_url( 'docs/getting-started/how-free-trials-work/' );
		$websites_url        = \WPMUDEV\Hub\Connector\Data::get()->server_url( 'hub2/' );
		$security_info_url   = \WPMUDEV\Hub\Connector\Data::get()->server_url( 'manuals/hub-security/' );
		$support_url         = \WPMUDEV\Hub\Connector\Data::get()->server_url( 'hub/support/' );
		$account_details_url = \WPMUDEV\Hub\Connector\Data::get()->server_url( 'hub2/account/details/' );

		if ( isset( $_GET['api_error'] ) ) {
			// Get errors.
			$api_error  = sanitize_key( wp_unslash( $_GET['api_error'] ) );
			$auth_error = sanitize_key( wp_unslash( $_GET['auth_error'] ?? '' ) );

			if ( 1 === (int) $api_error || 'auth' === $api_error ) {
				switch ( $auth_error ) {
					case 'google_linked':
						$error = sprintf(
						// translators: %s Account detail URL.
							__(
								'You are currently using your Google account as your preferred login method. If you wish to login with your WPMU DEV email & password instead, please change the <strong>Login Method</strong> in <a href="%s" target="_blank">your WPMU DEV account</a>.',
								'defender-security'
							),
							$account_details_url
						);
						break;
					case 'google_unlinked':
						$error = sprintf(
						// translators: %s Account detail URL.
							__(
								'You are currently using your WPMU DEV email & password as your preferred login method. If you wish to login with your Google account instead, please change the <strong>Login Method</strong> in <a href="%s" target="_blank">your WPMU DEV account</a>.',
								'defender-security'
							),
							$account_details_url
						);
						break;
					case 'reauth_google':
						$error = sprintf(
						// translators: %1$s Account detail URL, %2$s Reset URL.
							__(
								'Due to security improvements, you will need to re-link your Google account in the Hub. Please log in with your WPMU DEV email & password for now, then set up your preferred <strong>Login Method</strong> in <a href="%1$s" target="_blank">your WPMU DEV account</a>. Forgot your password? You can <a href="%2$s" target="_blank">reset it here</a>.',
								'defender-security'
							),
							$account_details_url,
							$reset_url
						);
						break;
					default:
						// Invalid credentials.
						$error = sprintf(
							'%s<br><a href="%s" target="_blank"><strong>%s</strong></a>',
							esc_html__( 'Your login details were incorrect. Please make sure you\'re using your WPMU DEV email and password and try again.', 'defender-security' ),
							$reset_url,
							esc_html__( 'Forgot your password?', 'defender-security' )
						);
						break;
				}
			} else {
				switch ( $api_error ) {
					case 'in_trial':
						$error = sprintf(
							'%s<br><a href="%s" target="_blank">%s</a>',
							sprintf(
							// translators: %1$s Rest URL, %2$s Upgrade URL, %3$s Trial URL.
								__(
									'This domain has previously been registered with us by the user %1$s. To use WPMU DEV on this domain, you can either log in with the original account (you can <a target="_blank" href="%2$s">reset your password</a>) or <a target="_blank" href="%3$s">upgrade your trial</a> to a full membership. Trial accounts can\'t use previously registered domains - <a target="_blank" href="%4$s">here\'s why</a>.',
									'defender-security'
								),
								'<strong style="word-break: break-all;">' . esc_html( $_GET['display_name'] ) . '</strong>', // phpcs:ignore
								$reset_url,
								$skip_trial_url,
								$trial_info_url
							),
							$support_url,
							__( 'Contact support if you need further assistance &raquo;', 'defender-security' )
						);
						break;
					case 'already_registered':
						$error = sprintf(
						// translators: %1$d Account name, %2$s Security info, %3$s Hub URL, %4$s Support URL.
							__(
								'This site is currently registered to %1$s. For <a target="_blank" href="%2$s">security reasons</a> they will need to go to the <a target="_blank" href="%3$s">WPMU DEV Hub</a> and remove this domain before you can log in. If you do not have access to that account, and have no way of contacting that user, please <a target="_blank" href="%4$s">contact support for assistance</a>.',
								'defender-security'
							),
							'<strong style="word-break: break-all;">' . esc_html( $_GET['display_name'] ) . '</strong>', // phpcs:ignore.
							$security_info_url,
							$websites_url,
							$support_url
						);
						break;
					case 'banned_account':
						$error = sprintf(
						// translators: %s Support URL.
							__( 'This domain cannot be registered to your WPMU DEV account.<br><a href="%s">Contact Accounts & Billing if you need further assistance »</a>', 'defender-security' ),
							\WPMUDEV\Hub\Connector\Data::get()->server_url( 'hub2/#ask-question' )
						);
						break;
					case 'expired_membership':
						$error = sprintf(
						// translators: %1$s Hub Account URL, %2$s: Switch to Free URL.
							__(
								'Login failed — your WPMU DEV membership has expired. Renew now to regain full access, or switch to our free plan to continue managing all your site in the Hub.<br/><br/><a class="sui-button sui-button-blue" href="%1$s" target="_blank">Renew Membership</a>&nbsp;<a class="sui-button sui-button-ghost" href="%2$s" target="_blank">Switch to Free</a>',
								'defender-security'
							),
							\WPMUDEV\Hub\Connector\Data::get()->server_url( 'hub2/account/' ),
							\WPMUDEV\Hub\Connector\Data::get()->server_url( 'hub2/?switch-free=1' )
						);
						break;
					case 'invalid_nonce':
					case 'invalid_double_submit_cookie':
					case 'invalid_google_creds':
					case '':
						$error = __( 'Google login failed. Please try again.', 'defender-security' );
						break;
					default:
						// Use the actual error message passed through from the sync poll if available.
						if ( ! empty( $_GET['api_error_msg'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
							$error = sanitize_text_field( wp_unslash( $_GET['api_error_msg'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
						} else {
							$error = __( 'Unknown error. Please update the WPMU DEV Dashboard plugin and try again.', 'defender-security' );
						}
						break;
				}
			}
		} elseif ( ! empty( $_REQUEST['connection_error'] ) ) {
			// Variable `$connection_error` is set by the UI function `render_dashboard`.
			$error = sprintf(
				'%s<br>%s<br><em>%s</em>',
				__( 'Your server had a problem connecting to WPMU DEV. Please try again.', 'defender-security' ),
				__( 'If this problem continues, please contact your host with this error message and ask:', 'defender-security' ),
				sprintf(
				// translators: url to API.
					__( '"Is PHP on my server properly configured to be able to contact %s with a POST HTTP request via fsockopen or CURL?"', 'defender-security' ),
					\WPMUDEV\Hub\Connector\Data::get()->server_url()
				)
			);
		} elseif ( ! empty( $_REQUEST['invalid_key'] ) ) {
			// Invalid API key.
			$error = __( 'Your API Key was invalid. Please try again.', 'defender-security' );
		}

		/**
		 * Filter to modify auth error text.
		 *
		 * @since 1.0.0
		 *
		 * @param string $error  Error message.
		 * @param string $plugin Plugin identifier.
		 */
		return apply_filters( 'wpmudev_hub_connector_get_auth_error', $error, self::PLUGIN_IDENTIFIER );
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
	}

	/**
	 * Get Hub Google login URL (https://wpmudev.com/api/dashboard/v2/google-auth).
	 *
	 * @return string
	 */
	public static function get_hub_google_login_url(): string {
		return \WPMUDEV\Hub\Connector\Data::get()->server_url( 'api/dashboard/v2/google-auth' );
	}

	/**
	 * Get connection URL for Hub.
	 *
	 * @param string $target_page   The target page to connect to.
	 * @param string $utm_campaign  The UTM campaign to append to the URL.
	 *
	 * @return string The connection URL.
	 */
	public static function get_connect_site_url( string $target_page = 'wp-defender', string $utm_campaign = '' ): string {
		$args = array();

		if ( self::should_redirect_to_dashboard() ) {
			$args['page'] = 'wpmudev';
		} else {
			$args = self::get_connection_args( $target_page );
		}

		if ( ! empty( $utm_campaign ) ) {
			$args['utm_campaign'] = sanitize_text_field( $utm_campaign );
		}

		$admin_url = self::get_admin_url();

		return add_query_arg( $args, $admin_url );
	}

	/**
	 * Get the Hub Connector callback URL inside Defender.
	 *
	 * @param string $target_page  The target page to connect to.
	 * @param string $utm_campaign The UTM campaign to append to the URL.
	 *
	 * @return string
	 */
	public static function get_hub_connector_callback_url( string $target_page = 'wp-defender', string $utm_campaign = '' ): string {
		$args = self::get_connection_args( $target_page );

		if ( ! empty( $utm_campaign ) ) {
			$args['utm_campaign'] = sanitize_text_field( $utm_campaign );
		}

		return add_query_arg( $args, self::get_admin_url() );
	}

	/**
	 * Check if should redirect to WPMUDEV Dashboard.
	 *
	 * @return bool
	 */
	private static function should_redirect_to_dashboard(): bool {
		return ! self::is_wpmudev_dashboard_connected() && class_exists( '\WPMUDEV_Dashboard' );
	}

	/**
	 * Check if WPMUDEV Dashboard is connected.
	 *
	 * @return bool
	 */
	public static function is_wpmudev_dashboard_connected(): bool {
		if ( ! class_exists( '\WPMUDEV_Dashboard' ) ) {
			return false;
		}

		$dashboard_api = \WPMUDEV_Dashboard::$api ?? null;

		return is_object( $dashboard_api ) &&
				method_exists( $dashboard_api, 'get_membership_status' ) &&
				method_exists( $dashboard_api, 'has_key' ) &&
				$dashboard_api->has_key();
	}

	/**
	 * Get connection arguments for URL.
	 *
	 * @param string $target_page The target page.
	 * @param string $module_slug Optional module slug to include for post-connection auto-enable.
	 * @return array
	 */
	private static function get_connection_args( string $target_page, string $module_slug = '' ): array {
		$args = array(
			'page'                   => sanitize_text_field( $target_page ),
			'_def_nonce'             => wp_create_nonce( self::CONNECTION_ACTION ),
			'page_action'            => self::CONNECTION_ACTION,
			'hub_connector_callback' => 1,
		);

		if ( '' !== $module_slug ) {
			$args['module_slug'] = sanitize_text_field( $module_slug );
		}

		return $args;
	}

	/**
	 * Get appropriate admin URL.
	 *
	 * @return string
	 */
	private static function get_admin_url(): string {
		return is_network_admin() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
	}

	/**
	 * Get the site domain.
	 *
	 * @return string
	 */
	public static function get_site_domain(): string {
		return \WPMUDEV\Hub\Connector\Data::get()->network_site_url();
	}

	/**
	 * Get Hub Login Auth URL (https://wpmudev.com/api/dashboard/v2/site-authenticate).
	 *
	 * @return string
	 */
	public static function get_hub_site_login_auth_url(): string {
		return \WPMUDEV\Hub\Connector\API::get()->rest_url( 'site-authenticate' );
	}

	/**
	 * Hub member profile for React UIs (same API as other WPMU DEV plugins: Data::profile_data).
	 *
	 * @return array<string, string>|null
	 */
	public static function get_profile_data_for_ui(): ?array {
		if ( ! class_exists( '\WPMUDEV\Hub\Connector\Data' ) ) {
			return null;
		}

		$api_logged_in = self::is_logged_in();
		$is_pro        = wd_di()->get( WPMUDEV::class )->is_pro();

		if ( ! $api_logged_in && ! $is_pro ) {
			return null;
		}

		$raw = \WPMUDEV\Hub\Connector\Data::get()->profile_data( true );

		if ( ! is_array( $raw ) || empty( $raw['user_name'] ) ) {
			return null;
		}

		$display_name = isset( $raw['name'] ) ? (string) $raw['name'] : '';
		$user_name    = isset( $raw['user_name'] ) ? (string) $raw['user_name'] : '';
		$avatar       = isset( $raw['avatar'] ) ? (string) $raw['avatar'] : '';

		$initial = '' !== $display_name ? strtoupper( substr( $display_name, 0, 1 ) ) : '';

		return array(
			'initials'               => $initial,
			'avatar'                 => $avatar,
			'profileBackgroundColor' => '' !== $avatar ? '#f8f8f8' : '#0059ff',
			'profileFontColor'       => '#ffffff',
			'userName'               => $user_name,
			'email'                  => is_email( $user_name ) ? $user_name : '',
			'displayName'            => $display_name,
		);
	}

	/**
	 * Get Hub register URL with site connection parameters.
	 *
	 * @param string $current_page The current page.
	 * @param string $post_sync_redirect Optional. URL to redirect to after sync completes. Default is empty string.
	 *
	 * @return string
	 */
	public static function get_hub_register_url( string $current_page = 'wp-defender', string $post_sync_redirect = '' ): string {
		// Fallback base URL when the Hub Connector library is not loaded.
		$base_url = 'https://wpmudev.com/register';

		if ( class_exists( '\WPMUDEV\Hub\Connector\Data' ) ) {
			$base_url = \WPMUDEV\Hub\Connector\Data::get()->server_url( 'register' );
		}

		// Get the hub connection URL.
		$hub_connect_url = self::get_hub_connector_callback_url( $current_page );

		// Prepare redirect URL with callback and auth nonce.
		$auth_nonce    = wp_create_nonce( 'auth_nonce' );
		$callback_args = array(
			'hub_connector_callback' => 1,
			'auth_nonce'             => $auth_nonce,
		);
		// rawurlencode() needed so the nested URL doesn't bleed into the outer query string.
		if ( '' !== $post_sync_redirect ) {
			$callback_args['post_sync_redirect'] = rawurlencode( esc_url_raw( $post_sync_redirect ) );
		}
		$redirect_url = add_query_arg( $callback_args, $hub_connect_url );

		// URL arguments for registration URL.
		// Do NOT REMOVE rawurlencode() site_connect_url — it is required.
		$register_args = array(
			'signup'           => 'site-connect',
			'site_connect_url' => rawurlencode( $redirect_url ),
			'utm_medium'       => 'plugin',
			'utm_source'       => self::PLUGIN_IDENTIFIER,
			'utm_campaign'     => 'defender_firewall_antibot',
			'utm_content'      => 'hub-connector',
		);

		return add_query_arg( $register_args, $base_url );
	}

	/**
	 * Get Hub forgot password URL.
	 *
	 * @return string
	 */
	public static function get_hub_forgot_password_url(): string {
		$base_url = 'https://wpmudev.com/forgot-password';

		if ( class_exists( '\WPMUDEV\Hub\Connector\Data' ) ) {
			$base_url = \WPMUDEV\Hub\Connector\Data::get()->server_url( 'forgot-password' );
		}

		$hub_connect_url = self::get_hub_connector_callback_url( 'wp-defender', 'defender_forgot_password' );
		$auth_nonce      = wp_create_nonce( 'auth_nonce' );
		$redirect_url    = add_query_arg(
			array(
				'hub_connector_callback' => 1,
				'auth_nonce'             => $auth_nonce,
			),
			$hub_connect_url
		);

		// Do NOT rawurlencode() site_connect_url — add_query_arg() encodes values internally; double-encoding breaks the callback URL on the Hub side.
		return add_query_arg(
			array(
				'site_connect_url' => $redirect_url,
				'utm_medium'       => 'plugin',
				'utm_source'       => self::PLUGIN_IDENTIFIER,
				'utm_campaign'     => 'defender_forgot_password',
				'utm_content'      => 'hub-connector',
			),
			$base_url
		);
	}
}
