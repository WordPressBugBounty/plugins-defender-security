<?php
/**
 * Handles the main admin page.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Event;
use Calotes\Helper\HTTP;
use Calotes\Helper\Route;
use WP_Defender\Model\Setting\Login_Lockout;
use WP_Defender\Model\Setting\Notfound_Lockout;
use WP_Defender\Model\Setting\User_Agent_Lockout;
use WP_Defender\Traits\Defender_Dashboard_Client;
use WP_Defender\Traits\IO;
use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Traits\Formats;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component\Feature_Modal;
use WP_Defender\Component\Hub_Connector as Hub_Connector_Component;
use WP_Defender\Model\Setting\Audit_Logging as Audit_Logging_Settings;
use WP_Defender\Model\Setting\Global_Ip_Lockout;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Component\IP\Global_IP as Global_IP_Component;
use WP_Defender\Model\Setting\Session_Protection;
use WP_Defender\Controller\Session_Protection as Session_Protection_Controller;

/**
 * Handles the main admin page.
 */
class Dashboard extends Event {

	use IO;
	use Formats;
	use Defender_Dashboard_Client;

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	public $slug = 'wp-defender';

	/**
	 * Site option key for the one-time report-schedule upgrade notice.
	 */
	public const REPORT_SCHEDULE_NOTICE_OPTION = 'wd_show_report_schedule_notice';

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 */
	public function __construct() {
		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
		$this->add_main_page();
		$this->register_routes();
		add_action( 'defender_enqueue_assets', array( $this, 'enqueue_assets' ) );
		add_filter( 'custom_menu_order', '__return_true' );
		add_filter( 'menu_order', array( $this, 'menu_order' ) );
		add_action( 'admin_init', array( $this, 'maybe_redirect_notification_request' ), 99 );
	}

	/**
	 * Because we move the notifications on separate modules, so links from HUB should be redirected to correct URL.
	 *
	 * @return void
	 */
	public function maybe_redirect_notification_request(): void {
		$page = HTTP::get( 'page' );
		if ( ! in_array( $page, array( 'wdf-scan', 'wdf-ip-lockout', 'wdf-hardener', 'wdf-logging' ), true ) ) {
			return;
		}
		$view = HTTP::get( 'view' );
		if ( in_array( $view, array( 'reporting', 'notification', 'report' ), true ) ) {
			wp_safe_redirect( network_admin_url( 'admin.php?page=wdf-notification' ) );
			exit;
		}
	}

	/**
	 * Filter out the defender menu for changing text.
	 *
	 * @param  array $menu_order  The current menu order.
	 *
	 * @return array
	 */
	public function menu_order( $menu_order ) {
		global $submenu;
		if ( isset( $submenu['wp-defender'] ) ) {
			$defender_menu       = $submenu['wp-defender'];
			$defender_menu[0][0] = esc_html__( 'Dashboard', 'defender-security' );
			$defender_menu       = array_values( $defender_menu );
			// Change the global $submenu variable, because otherwise the menu name/order will not change.
			$submenu['wp-defender'] = $defender_menu; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		}

		global $menu;
		// Get the total scanning active issues.
		$count = wd_di()->get( \WP_Defender\Component\Scan::class )->indicator_issue_count();

		$indicator = $count > 0
			? ' <span class="update-plugins wd-issue-indicator-sidebar"></span>'
			: null;
		foreach ( $menu as $k => $item ) {
			if ( 'wp-defender' === $item[2] ) {
				// Add a badge next to the "Defender" menu item in the global $menu variable.
				$menu[ $k ][0] .= $indicator; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			}
		}

		return $menu_order;
	}

	/**
	 * Registers the main page in the WordPress admin menu.
	 */
	protected function add_main_page() {
		$this->register_page(
			$this->get_page_title(),
			$this->parent_slug,
			array( $this, 'main_view' ),
			null,
			$this->get_menu_icon(),
			$this->get_menu_title()
		);
	}

	/**
	 * Renders the main view for this page.
	 */
	public function main_view() {
		$this->render( 'main' );
	}

	/**
	 * Page-specific data for a concrete controller.
	 *
	 * @return array
	 */
	protected function get_page_data(): array {
		$security_tweaks = wd_di()->get( \WP_Defender\Controller\Security_Tweaks::class );
		$security_tweaks->refresh_tweaks_status();
		$security_tweaks_data = $security_tweaks->dashboard_widget();

		$audit_model = wd_di()->get( Audit_Logging_Settings::class );
		$firewall    = wd_di()->get( Firewall::class )->get_summary();
		// Different lockout types.
		$enabled_login = wd_di()->get( Login_Lockout::class )->enabled;
		$enabled_nf    = wd_di()->get( Notfound_Lockout::class )->enabled;
		$enabled_ua    = wd_di()->get( User_Agent_Lockout::class )->enabled;

		return array(
			'hide_onboarding'             => ! wd_di()->get( HUB::class )->get_onboarding_status(),
			'defenderSetupNonce'          => wp_create_nonce( 'defender_quick_setup' ),
			'securityTweaks'              => $security_tweaks_data['summary']['issues_count'],
			'scanData'                    => array(
				'numberIssues' => wd_di()->get( \WP_Defender\Component\Scan::class )->indicator_issue_count(),
				'settings'     => wd_di()->get( \WP_Defender\Model\Setting\Scan::class )->export(),
				// Scan routes & nonces are set above.
			),
			'firewallData'                => array(
				'enabledLocalFirewall' => $enabled_login || $enabled_nf || $enabled_ua,
				'enabledLogin'         => $enabled_login,
				'enabledNotFound'      => $enabled_nf,
				'enabledUserAgent'     => $enabled_ua,
				'loginLockoutMonth'    => $firewall['lockout_login_this_month'],
				'nfLockoutMonth'       => $firewall['lockout_404_this_month'],
				'uaLockoutMonth'       => $firewall['lockout_ua_this_month'],
				'antibot'              => wd_di()->get( Antibot_Global_Firewall::class )->data_frontend(),
			),
			'site_id'                     => wd_di()->get( WPMUDEV::class )->get_site_id(),
			'auditData'                   => array(
				'enabled' => $audit_model->is_active(),
			),
			'sessionProtection'           => wd_di()->get( Session_Protection::class )->export(),
			'show_report_schedule_notice' => (bool) get_site_option( self::REPORT_SCHEDULE_NOTICE_OPTION, false ),
		);
	}

	/**
	 * Enqueues scripts and styles for this page.
	 * Only enqueues assets if the page is active.
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}

		$wizard_action = HTTP::get( 'wizard_action' );
		$wizard_source = HTTP::get( 'source' );

		// Fallback completion marker for setup wizard integrations rendered on dashboard.
		// This prevents onboarding loops if client-side completion request fails.
		if (
			'setup_wizard' === $wizard_source
			&& in_array( $wizard_action, array( 'view_results', 'close_wizard', 'finish_wizard' ), true )
			&& current_user_can( 'manage_options' )
		) {
			update_site_option( 'wp_defender_shown_activator', true );
		}

		$show_onboarding       = \WP_Defender\Model\Onboard::maybe_show_onboarding();
		$api_error             = HTTP::get( 'api_error' );
		$hub_connection_source = HTTP::get( 'hub_connection_source' );
		$hub_connect_recovery  = ! $show_onboarding
			&& is_string( $api_error )
			&& '' !== $api_error
			&& 'profile_menu' !== $hub_connection_source
			&& ! Hub_Connector_Component::is_logged_in()
			&& ! Hub_Connector_Component::is_wpmudev_dashboard_connected();

		if ( $show_onboarding || $hub_connect_recovery ) {
			add_filter( 'admin_body_class', array( $this, 'admin_body_class' ) );
		}

		$handle = 'defender-ui-dashboard';
		wp_enqueue_script(
			$handle,
			WP_DEFENDER_BASE_URL . 'assets/js/dashboard-ui.js',
			array( 'def-vue', 'def-manifest', 'def-core-ui', 'defender', 'wp-i18n' ),
			DEFENDER_VERSION,
			true
		);
		wp_set_script_translations( $handle, 'wpdef' );

		$setup_wizard_data = wd_di()->get( Setup_Wizard::class )->data_frontend();
		$tracking_data     = wd_di()->get( Data_Tracking::class )->get_dashboard_notice_data();
		$dashboard_data    = $this->dump_routes_and_nonces();
		$firewall_data     = wd_di()->get( Firewall::class )->dump_routes_and_nonces();
		$scan_data         = wd_di()->get( \WP_Defender\Controller\Scan::class )->dump_routes_and_nonces();
		$routes            = array_merge(
			$setup_wizard_data['routes'] ?? array(),
			$tracking_data['routes'] ?? array(),
			$dashboard_data['routes'] ?? array(),
			$firewall_data['routes'] ?? array(),
			$scan_data['routes'] ?? array(),
		);
		$nonces            = array_merge(
			$setup_wizard_data['nonces'] ?? array(),
			$tracking_data['nonces'] ?? array(),
			$dashboard_data['nonces'] ?? array(),
			$firewall_data['nonces'] ?? array(),
			$scan_data['nonces'] ?? array(),
		);
		unset( $setup_wizard_data['routes'], $setup_wizard_data['nonces'] );
		unset( $tracking_data['routes'], $tracking_data['nonces'] );
		unset( $firewall_data['routes'], $firewall_data['nonces'] );
		wp_localize_script(
			$handle,
			'defenderUIData',
			array_merge(
				$this->get_shared_data(),
				$this->get_page_data(),
				// Welcome modal's details.
				wd_di()->get( Feature_Modal::class )->get_dashboard_modals(),
				// Specific data.
				array(
					'showOnboarding' => $show_onboarding,
					'routes'         => $routes,
					'nonces'         => $nonces,
				),
				$setup_wizard_data,
				$tracking_data,
				wd_di()->get( \WP_Defender\Controller\Scan::class )->get_initial_scan_data()
			)
		);

		wp_enqueue_style(
			$handle,
			WP_DEFENDER_BASE_URL . 'assets/css/showcase.css',
			array(),
			DEFENDER_VERSION
		);

		$this->enqueue_main_assets();
	}

	/**
	 * Adds onboarding body classes on dashboard when onboarding wizard is active.
	 *
	 * @param  string $classes  Existing admin body classes.
	 *
	 * @return string
	 */
	public function admin_body_class( $classes ): string {
		$classes .= ' wdf-onboarding-active ';

		return $classes;
	}

	/**
	 * Returns the current hardening (security tweaks) issue count via AJAX.
	 *
	 * @return Response
	 * @defender_route
	 * @defender_redirect
	 */
	public function get_hardening_count(): Response {
		$security_tweaks = wd_di()->get( \WP_Defender\Controller\Security_Tweaks::class )->dashboard_widget();

		return new Response(
			true,
			array(
				'count' => (int) ( $security_tweaks['summary']['issues_count'] ?? 0 ),
			)
		);
	}

	/**
	 * Handles the request to hide new features modal.
	 *
	 * @param  Request $request  The request object containing data.
	 *
	 * @return Response The response object indicating success or failure.
	 * @defender_route
	 */
	public function hide_new_features( Request $request ): Response {
		$data      = $request->get_data(
			array(
				'intention' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		$intention = $data['intention'] ?? false;
		if ( 'welcome_modal' === $intention ) {
			Feature_Modal::delete_modal_key();
		}

		return new Response( true, array() );
	}

	/**
	 * Activate Global IP submodule with the enabled Auto sync option.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function activate_global_ip(): Response {
		// Changes for Global IP.
		$model                     = wd_di()->get( Global_Ip_Lockout::class );
		$model->enabled            = true;
		$model->blocklist_autosync = true;
		$model->save();
		// Clear Global IP reminder.
		wd_di()->get( Global_IP_Component::class )->delete_dashboard_notice_reminder();
		// Changes for Hub.
		Config_Hub_Helper::set_clear_active_flag();

		return new Response(
			true,
			array(
				'redirect' => network_admin_url( 'admin.php?page=wdf-ip-lockout&view=global-ip' ),
				'interval' => 1,
			)
		);
	}

	/**
	 * Activate Session Protection submodule.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function activate_session_protection(): Response {
		$model          = wd_di()->get( Session_Protection::class );
		$model->enabled = true;
		$model->save();
		// Changes for Hub.
		Config_Hub_Helper::set_clear_active_flag();

		return new Response(
			true,
			array(
				'redirect' => network_admin_url( 'admin.php?page=wdf-advanced-tools&view=session-protection' ),
				'interval' => 1,
			)
		);
	}

	/**
	 * Remove Global IP notice reminder.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function remove_global_ip_notice_reminder(): Response {
		wd_di()->get( Global_IP_Component::class )->delete_dashboard_notice_reminder();

		return new Response( true, array() );
	}

	/**
	 * Dismiss the one-time report-schedule notice set during the 6.1.0 upgrade.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function dismiss_report_schedule_notice(): Response {
		delete_site_option( self::REPORT_SCHEDULE_NOTICE_OPTION );

		return new Response( true, array() );
	}

	/**
	 * Toggle a dashboard feature by feature key.
	 *
	 * @param Request $request The current request data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function toggle_feature( Request $request ): Response {
		$data    = $request->get_data(
			array(
				'feature' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		$feature = $data['feature'] ?? '';

		$feature_controllers = array(
			'antibot'            => Antibot_Global_Firewall::class,
			'audit'              => Audit_Logging::class,
			'session_protection' => Session_Protection_Controller::class,
		);
		if ( isset( $feature_controllers[ $feature ] ) ) {
			return wd_di()->get( $feature_controllers[ $feature ] )->save_settings( $request );
		}

		return new Response(
			false,
			array(
				'message' => esc_html__( 'Unsupported feature toggle request.', 'defender-security' ),
			)
		);
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings() {
		wd_di()->get( Feature_Modal::class )->upgrade_site_options();

		delete_site_option( self::REPORT_SCHEDULE_NOTICE_OPTION );
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		[ $endpoints, $nonces ] = Route::export_routes( 'dashboard' );
		$firewall               = wd_di()->get( Firewall::class );

		return array_merge(
			wd_di()->get( Feature_Modal::class )->get_dashboard_modals(),
			array(
				'scan'              => wd_di()->get( Scan::class )->data_frontend(),
				'firewall'          => $firewall->data_frontend(),
				'blocklist_monitor' => wd_di()->get( Blocklist_Monitor::class )->data_frontend(),
				'blacklist'         => array(
					'nonces'    => $nonces,
					'endpoints' => $endpoints,
				),
				'two_fa'            => wd_di()->get( Two_Factor::class )->data_frontend(),
				'advanced_tools'    => array(
					'mask_login'       => wd_di()->get( Mask_Login::class )->dashboard_widget(),
					'security_headers' => wd_di()->get( Security_Headers::class )->dashboard_widget(),
					'pwned_passwords'  => wd_di()->get( Password_Protection::class )->dashboard_widget(),
					'captcha'          => wd_di()->get( Captcha::class )->dashboard_widget(),
					'strong_passwords' => wd_di()->get( Strong_Password::class )->dashboard_widget(),
				),
				'security_tweaks'   => wd_di()->get( Security_Tweaks::class )->dashboard_widget(),
				'notifications'     => wd_di()->get( Notification::class )->data_frontend(),
				'settings'          => wd_di()->get( Main_Setting::class )->data_frontend(),
				'countries'         => $firewall->dashboard_widget(),
				'global_ip'         => wd_di()->get( Global_Ip::class )->data_frontend(),
				'hub_connector'     => wd_di()->get( Hub_Connector::class )->data_frontend(),
				'antibot'           => wd_di()->get( Antibot_Global_Firewall::class )->data_frontend(),
			)
		);
	}

	/**
	 * Converts the current object state to an array.
	 *
	 * @return array The array representation of the object.
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Imports data into the model.
	 *
	 * @param  array $data  Data to be imported into the model.
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Exports strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		return array();
	}
}
