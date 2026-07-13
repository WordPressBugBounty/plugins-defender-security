<?php
/**
 * Handles Hub Connector feature.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use Calotes\Component\Response;
use WP_Defender\Controller;
use WP_Defender\Component\Hub_Connector as Hub_Connector_Component;
use WP_Defender\Model\Setting\Antibot_Global_Firewall_Setting;
use WP_Defender\Traits\Defender_Dashboard_Client;

/**
 * Handles Hub Connector feature.
 */
class Hub_Connector extends Controller {
	use Defender_Dashboard_Client;

	public const TRANSIENT_KEY = 'wpdef_maybe_hub_connection_attempt';

	/**
	 * Service for handling logic.
	 *
	 * @var Hub_Connector_Component
	 */
	public $service;

	/**
	 * Constructor for the Hub_Connector class.
	 *
	 * @param Hub_Connector_Component $service The service object.
	 */
	public function __construct( Hub_Connector_Component $service ) {
		$this->service = $service;
		$this->register_routes();

		add_action( 'admin_init', array( $this, 'maybe_hcm_connection_attempt' ) );
		add_action( 'wp_ajax_wpdef_check_hub_sync_status', array( $this, 'ajax_check_hub_sync_status' ) );
		add_action( 'wpmudev_hub_connector_first_sync_completed', array( $this, 'clear_syncing_state' ) );
	}

	/**
	 * Maybe member is trying to connect via Hub Connection Module.
	 */
	public function maybe_hcm_connection_attempt() {
		$module_slug = defender_get_data_from_request( 'module_slug', 'g' );
		$is_callback = defender_get_data_from_request( 'hub_connector_callback', 'g' );

		if ( is_string( $module_slug ) && '' !== $module_slug && is_string( $is_callback ) && '' !== $is_callback ) {
			set_site_transient(
				self::TRANSIENT_KEY,
				array(
					'module_slug' => $module_slug,
				),
				MINUTE_IN_SECONDS
			);
		}
	}

	/**
	 * Disconnect site from Hub.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function disconnect_site(): Response {
		$this->logout();

		return new Response(
			true,
			array(
				'message'    => esc_html__( 'Site disconnected successfully!', 'defender-security' ),
				'auto_close' => true,
			)
		);
	}

	/**
	 * Activate Dashboard plugin.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function activate_dashboard_plugin(): Response {
		$plugin_path = 'wpmudev-updates/update-notifications.php';
		$result      = activate_plugin( $plugin_path );
		if ( is_wp_error( $result ) ) {
			return new Response(
				false,
				array(
					'message' => $result->get_error_message(),
				)
			);
		}

		return new Response(
			true,
			array(
				'message'  => esc_html__( 'Dashboard plugin has been activated. You should be redirected to sign-in page shortly.', 'defender-security' ),
				'redirect' => $this->service->get_url(),
			)
		);
	}

	/**
	 * AJAX handler to check Hub sync status.
	 *
	 * @return void
	 */
	public function ajax_check_hub_sync_status() {
		check_ajax_referer( 'auth_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Unauthorized', 'defender-security' ) ), 403 );
		}

		$sync = $this->service->sync();
		if ( is_wp_error( $sync ) && 'not_logged_in' !== $sync->get_error_code() ) {
			$this->clear_syncing_state();

			wp_send_json_error(
				array(
					'is_synced'     => false,
					'error_code'    => $sync->get_error_code(),
					'error_message' => $sync->get_error_message(),
				),
				403
			);
		}

		$is_logged_in = Hub_Connector_Component::is_logged_in();
		$this->clear_syncing_state();

		if ( $is_logged_in ) {
			// Lets feature controllers auto-enable themselves via the module_slug transient.
			do_action( 'wpdef_hub_connector_synced' );
		}

		wp_send_json_success(
			array(
				'is_synced' => $is_logged_in,
			)
		);
	}

	/**
	 * Clears the temporary Hub syncing state.
	 *
	 * @return void
	 */
	public function clear_syncing_state(): void {
		delete_site_transient( Hub_Connector_Component::SYNCING_TRANSIENT_KEY );
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		return array_merge(
			array(
				'button_label'           => $this->service->get_button_label(),
				'is_dash_installed'      => $this->is_dash_installed(),
				'is_dash_activated'      => $this->is_dash_activated(),
				'dash_url'               => add_query_arg( 'page', 'wpmudev', is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) ),
				'is_hub_connected'       => $this->is_site_connected_to_hub_via_hcm_or_dash(),
				'is_logged_in'           => Hub_Connector_Component::is_logged_in() || Hub_Connector_Component::is_wpmudev_dashboard_connected(),
				'is_dashboard_connected' => Hub_Connector_Component::is_wpmudev_dashboard_connected(),
				'has_login_error'        => Hub_Connector_Component::has_error_in_login(),
				'login_error_msg'        => Hub_Connector_Component::get_auth_error(),
				'hub_auth_url'           => Hub_Connector_Component::get_hub_google_login_url(),
				'redirect_url'           => Hub_Connector_Component::get_hub_connector_callback_url(),
				'domain'                 => Hub_Connector_Component::get_site_domain(),
				'auth_nonce'             => wp_create_nonce( 'auth_nonce' ),
				'login_auth_url'         => Hub_Connector_Component::get_hub_site_login_auth_url(),
				'hub_signup_url'         => Hub_Connector_Component::get_hub_register_url(),
				'forgot_password_url'    => Hub_Connector_Component::get_hub_forgot_password_url(),
				'is_syncing'             => Hub_Connector_Component::is_syncing(),
				'logout_url'             => rest_url( 'hub-connector/v1/logout' ),
				'logout_nonce'           => wp_create_nonce( 'wp_rest' ),
				'hub_connector_url'      => array(
					'default'                   => $this->service->get_url(),
					'global-ip'                 => $this->service->get_url( 'wdf-ip-lockout', 'global-ip' ),
					'blocklist'                 => $this->service->get_url( 'wdf-ip-lockout', 'blocklist' ),
					'onboard'                   => $this->service->get_url( 'wp-defender', 'onboard' ),
					'dashboard'                 => $this->service->get_url( 'wp-defender', 'dashboard' ),
					'setting'                   => $this->service->get_url( 'wdf-setting', 'general' ),
					// Settings > Tools redirect for scan-item HC features (Known Vuln, Suspicious Code).
					'settings-redirect'         => $this->service->get_url( 'wdf-setting', 'tools' ),
					// Settings > Tools redirect; module slug auto-enables Blocklist Monitor.
					'settings-blocklist'        => $this->service->get_url( 'wdf-setting', 'tools', '', '', 'blocklist-monitor' ),
					// Scan page redirect for the Safe Repair HC feature.
					'scan'                      => $this->service->get_url( 'wdf-scan' ),
					// Global Firewall redirect; module slug auto-enables AntiBot.
					'global-firewall'           => $this->service->get_url( 'wdf-ip-lockout', 'global-ip', '', '', Antibot_Global_Firewall_Setting::MODULE_SLUG ),
					// Custom Rules redirect; module slug auto-enables Custom IP list sync.
					'custom-rules'              => $this->service->get_url( 'wdf-ip-lockout', 'custom-rules', '', '', Global_Ip::MODULE_SLUG ),
					// Custom one if a trigger is the Summary section.
					'summary-box'               => $this->service->get_url( 'wdf-ip-lockout', 'summary-box' ),
					// Custom one for Antibot notice shown on all Defender pages.
					'antibot-notice'            => $this->service->get_url( 'wdf-ip-lockout', '', 'def_antibot_survey_notice', 'hub_connector' ),
					// Signup URLs with post_sync_redirect embedded — Hub always calls back to Dashboard.
					'settings-redirect-signup'  => Hub_Connector_Component::get_hub_register_url( 'wp-defender', $this->service->get_url( 'wdf-setting', 'tools' ) ),
					'settings-blocklist-signup' => Hub_Connector_Component::get_hub_register_url( 'wp-defender', $this->service->get_url( 'wdf-setting', 'tools', '', '', 'blocklist-monitor' ) ),
					'scan-signup'               => Hub_Connector_Component::get_hub_register_url( 'wp-defender', $this->service->get_url( 'wdf-scan' ) ),
					'global-firewall-signup'    => Hub_Connector_Component::get_hub_register_url( 'wp-defender', $this->service->get_url( 'wdf-ip-lockout', 'global-ip', '', '', Antibot_Global_Firewall_Setting::MODULE_SLUG ) ),
					'custom-rules-signup'       => Hub_Connector_Component::get_hub_register_url( 'wp-defender', $this->service->get_url( 'wdf-ip-lockout', 'custom-rules', '', '', Global_Ip::MODULE_SLUG ) ),
				),
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Export to array
	 *
	 * @return array
	 */
	public function to_array() {
		return array();
	}

	/**
	 * Import data
	 *
	 * @param array $data The data to import.
	 */
	public function import_data( $data ) {}

	/**
	 * Export strings
	 *
	 * @return array
	 */
	public function export_strings() {
		return array();
	}

	/**
	 * Removes settings.
	 */
	public function remove_settings() {
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
	}
}
