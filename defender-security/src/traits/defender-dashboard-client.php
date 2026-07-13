<?php
/**
 * Handle Dashboard based functionalities of WPMUDEV class.
 *
 * @package WP_Defender\Traits
 */

namespace WP_Defender\Traits;

use WPMUDEV_Dashboard;
use WPMUDEV\Hub\Connector\API;
use WPMUDEV\Hub\Connector\Data;
use WP_Defender\Component\Config\Config_Hub_Helper;

trait Defender_Dashboard_Client {
	use \WP_Defender\Traits\Plugin;

	/**
	 * Get membership status.
	 *
	 * @return bool
	 */
	public function is_pro(): bool {
		return class_exists( '\WPMUDEV_Dashboard' ) && method_exists( $this, 'get_apikey' ) && $this->get_apikey() !== false;
	}

	/**
	 * Check if user is a paid one in WPMU DEV.
	 *
	 * @return bool
	 */
	public function is_member(): bool {
		if (
			$this->is_dash_activated() && method_exists( WPMUDEV_Dashboard::$upgrader, 'user_can_install' )
		) {
			return WPMUDEV_Dashboard::$upgrader->user_can_install(
				Config_Hub_Helper::WDP_ID,
				true
			);
		}

		return false;
	}

	/**
	 * Check if user is a WPMU DEV admin.
	 *
	 * @return bool
	 * @since 2.6.3
	 */
	public function is_wpmu_dev_admin(): bool {
		if (
			'dashboard' === $this->resolve_connection_mode() &&
			is_object( WPMUDEV_Dashboard::$site ) &&
			method_exists( WPMUDEV_Dashboard::$site, 'allowed_user' )
		) {
			return WPMUDEV_Dashboard::$site->allowed_user( get_current_user_id() );
		}

		return false;
	}

	/**
	 * Returns whether the current install is a Pro version.
	 *
	 * @return bool
	 */
	protected function is_pro_install(): bool {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$is_pro = file_exists( $this->get_abs_plugin_path_by_slug( WP_DEFENDER_PRO_PATH ) )
					&& is_plugin_active( WP_DEFENDER_PRO_PATH );

		return $is_pro;
	}

	/**
	 * Returns the page title.
	 *
	 * @return string Page title.
	 */
	public function get_page_title(): string {
		return $this->is_pro_install()
			? esc_html__( 'Defender Pro', 'defender-security' )
			: esc_html__( 'Defender', 'defender-security' );
	}

	/**
	 * Returns the sidebar menu title, including a "Pro" badge span when on a Pro install.
	 *
	 * @return string Menu title.
	 */
	public function get_menu_title(): string {
		if ( $this->is_pro_install() ) {
			return sprintf(
				'%1$s<span class="defender-admin-menu-pro-tag">%2$s</span>',
				esc_html__( 'Defender', 'defender-security' ),
				esc_html__( 'Pro', 'defender-security' )
			);
		}

		return esc_html__( 'Defender', 'defender-security' );
	}

	/**
	 * Return icon svg image.
	 *
	 * @return string
	 */
	public function get_menu_icon(): string {
		ob_start();
		?>
		<svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
			<path d="M7.44 1.12125L2.94 2.43125C2.09 2.68125 1.5 3.46125 1.5 4.35125V8.66125C1.5 11.5312 4.72 14.9612 8 14.9612C11.28 14.9612 14.5 11.5312 14.5 8.66125V4.35125C14.5 3.46125 13.91 2.68125 13.06 2.43125L8.56 1.12125C8.2 1.01125 7.81 1.01125 7.44 1.12125ZM13.06 8.66125C13.06 10.6912 10.53 13.5612 8 13.5612V7.96125H2.94V3.90125L8 2.43125V7.96125H13.06V8.66125Z" fill="#F0F6FC"/>
		</svg>
		<?php
		$svg = ob_get_clean();

		return 'data:image/svg+xml;base64,' . base64_encode( $svg ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Check if WPMU DEV Dashboard plugin is activated.
	 *
	 * @return bool
	 * @since 3.4.0
	 */
	public function is_dash_activated(): bool {
		return class_exists( 'WPMUDEV_Dashboard' );
	}

	/**
	 * Checks if WPMU DEV Dashboard plugin is installed.
	 *
	 * @return bool
	 * @since 4.10.0
	 */
	public function is_dash_installed(): bool {
		return file_exists( WP_PLUGIN_DIR . '/wpmudev-updates/update-notifications.php' );
	}

	/**
	 * Check if site is connected to HUB.
	 * Todo: after implementing the HCM, the Free version can get an API key if the site is connected to the Hub using
	 * HCM (without the Dashboard plugin). Does it make sense to use hub_connector_connected() method instead of
	 * the current one?
	 *
	 * @return bool
	 * @since 3.6.0 Added changes after the implementation of TFH on the hub.
	 * @since 3.4.0
	 */
	public function is_site_connected_to_hub(): bool {
		// The case if Pro version is activated, it is TFH account and a site is from 3rd party hosting.
		if (
			WP_DEFENDER_PRO_PATH === DEFENDER_PLUGIN_BASENAME
			&& method_exists( $this, 'is_another_hosted_site_connected_to_tfh' )
			&& $this->is_another_hosted_site_connected_to_tfh()
		) {
			return '' !== $this->get_api_key();
		} else {
			$hub_site_id = method_exists( $this, 'get_site_id' ) ? $this->get_site_id() : null;

			return is_int( $hub_site_id ) && $hub_site_id > 0;
		}
	}

	/**
	 * Check if HUB option is disabled, e.g. Global IP.
	 *
	 * @return bool
	 */
	public function is_disabled_hub_option(): bool {
		return 'none' === $this->resolve_connection_mode();
	}

	/**
	 * Get remote access.
	 */
	public function get_remote_access() {
		if ( ! class_exists( 'WPMUDEV_Dashboard' ) ) {
			return false;
		}

		// Use backward compatibility.
		if ( WPMUDEV_Dashboard::$version > '4.11.9' ) {
			return WPMUDEV_Dashboard::$settings->get( 'remote_access' );
		} else {
			return WPMUDEV_Dashboard::$site->get_option( 'remote_access' );
		}
	}
	/**
	 * Checks if the Hub connector module (HCM) is connected.
	 *
	 * @return bool True if connected, false otherwise.
	 */
	public static function get_hcm_status(): bool {
		return class_exists( 'WPMUDEV\Hub\Connector\API' ) && API::get()->is_logged_in();
	}

	/**
	 * Checks if the Dashboard plugin has a usable Hub connection.
	 *
	 * @return bool
	 */
	protected function is_dashboard_connected(): bool {
		return $this->is_dash_activated()
			&& is_object( WPMUDEV_Dashboard::$api )
			&& WPMUDEV_Dashboard::$api->has_key()
			&& (int) WPMUDEV_Dashboard::$api->get_site_id() > 0;
	}

	/**
	 * Resolve the active Hub connection mode for this request.
	 *
	 * @return string 'dashboard' | 'hub_connector' | 'none'
	 * @since 6.0.0
	 */
	public function resolve_connection_mode(): string {
		if ( $this->is_dashboard_connected() ) {
			return 'dashboard';
		} elseif ( self::get_hcm_status() ) {
			return 'hub_connector';
		}

		return 'none';
	}

	/**
	 * Checks if Hub Connector is connected. If Dash plugin is not installed Hub connector can take over.
	 *
	 * @return bool
	 */
	public function hub_connector_connected(): bool {
		return 'none' !== $this->resolve_connection_mode();
	}

	/**
	 * Upgrade the method to get api key from Dashboard plugin or Hub Connector module.
	 *
	 * @return string
	 */
	public function get_api_key(): string {
		if ( 'dashboard' === $this->resolve_connection_mode() ) {
			$api_key = WPMUDEV_Dashboard::$api->get_key();
		} elseif ( class_exists( 'WPMUDEV\Hub\Connector\API' ) ) {
			$api_key = API::get()->get_api_key();
		} else {
			$api_key = '';
		}

		return $api_key;
	}

	/**
	 * Get Membership type.
	 *
	 * @return string
	 */
	public function get_membership_type() {
		if ( 'dashboard' === $this->resolve_connection_mode() ) {
			return WPMUDEV_Dashboard::$api->get_membership_status();
		} elseif ( self::get_hcm_status() ) {
			return Data::get()->membership_type();
		}
		return 'free';
	}

	/**
	 * Check if the membership type is expired.
	 *
	 * @return bool True if membership is expired, false otherwise.
	 */
	public function is_expired_membership_type(): bool {
		return 'expired' === $this->get_membership_type();
	}

	/**
	 * Logout from hub.
	 *
	 * @return array|bool|\WP_Error
	 */
	public function logout() {
		return API::get()->logout();
	}

	/**
	 * Check if site is connected to HUB via HCM or Dash.
	 *
	 * @return bool
	 */
	public function is_site_connected_to_hub_via_hcm_or_dash(): bool {
		return $this->hub_connector_connected() || self::get_hcm_status();
	}
}
