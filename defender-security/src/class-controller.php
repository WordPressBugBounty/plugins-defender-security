<?php
/**
 * This class handles all routes and actions for a particular module.
 *
 * @package WP_Defender
 */

namespace WP_Defender;

use ReflectionClass;
use ReflectionMethod;
use Calotes\Helper\HTTP;
use WP_Defender\Traits\IO;
use WP_Defender\Traits\Plugin;
use WP_Defender\Traits\User;
use WP_Defender\Traits\Permission;
use WP_Defender\Component\Hub_Connector;
use WP_Defender\Traits\Defender_Dashboard_Client;

/**
 * The controller class.
 */
abstract class Controller extends \Calotes\Base\Controller {

	use IO;
	use User;
	use Permission;
	use Plugin;
	use Defender_Dashboard_Client;

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	protected $parent_slug = 'wp-defender';

	/**
	 * All the variables that we will show on frontend, both in the main page, or dashboard widget.
	 *
	 * @return array
	 */
	abstract public function data_frontend();

	/**
	 * Export the data of this module, we will use this for export to HUB, create a preset etc.
	 *
	 * @return array
	 */
	abstract public function to_array();

	/**
	 * Import the data of other source into this, it can be when HUB trigger the import, or user apply a preset.
	 *
	 * @param  array $data  Data from other source.
	 *
	 * @return null|void
	 */
	abstract public function import_data( array $data );

	/**
	 * Remove all settings, configs generated in this container runtime.
	 *
	 * @return void
	 */
	abstract public function remove_settings();

	/**
	 * Remove all data.
	 *
	 * @return void
	 */
	abstract public function remove_data();

	/**
	 * Export strings.
	 *
	 * @return array
	 */
	abstract public function export_strings();

	/**
	 * An internal cache.
	 *
	 * @var array
	 */
	private $cache = array();

	/**
	 * Queue mandatory assets.
	 */
	public function enqueue_main_assets() {
		if ( $this->is_page_active() ) {
			wp_enqueue_script( 'clipboard' );
			wp_enqueue_style( 'defender' );
			wp_enqueue_script( 'wpmudev-sui' );
		}
	}

	/**
	 * This too check if the current page is active, so we can queue right assets.
	 *
	 * @return bool
	 */
	public function is_page_active() {
		$current = HTTP::get( 'page' );

		return $current === $this->slug;
	}

	/**
	 * Quick handler to check nonce.
	 *
	 * @param  string $intention  Should give context to what is taking place and be the same when nonce was created.
	 * @param  string $method  Current request method.
	 *
	 * @return bool
	 */
	protected function verify_nonce( $intention, $method = 'get' ) {
		$nonce = 'get' === $method ? HTTP::get( '_def_nonce' ) : HTTP::post( '_def_nonce' );
		if ( ! wp_verify_nonce( $nonce, $intention ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Bind for submit data to DEV.
	 *
	 * @return void
	 */
	public function queue_to_sync_with_hub() {
		if ( ! wp_next_scheduled( 'defender_hub_sync' ) ) {
			wp_schedule_single_event( time(), 'defender_hub_sync' );
		}
	}

	/**
	 * Read through this class and generate a list of intention method, register it with the central.
	 * The methods that have annotation @defender_method will be registered automatically.
	 */
	public function register_routes() {
		foreach ( $this->get_methods() as $method ) {
			$doc_block = $method->getDocComment();
			if ( stristr( $doc_block, '@defender_route' ) ) {
				if ( 'register_routes' === $method->getName() ) {
					continue;
				}
				$is_public   = stristr( $doc_block, '@is_public' );
				$is_redirect = stristr( $doc_block, '@defender_redirect' );
				wd_central()->add_route( $method->getName(), static::class, ! $is_public, $is_redirect );
			}
		}
	}

	/**
	 * Return all methods from current class.
	 *
	 * @return ReflectionMethod[]
	 */
	private function get_methods() {
		$class = new ReflectionClass( static::class );

		return $class->getMethods( ReflectionMethod::IS_PUBLIC );
	}

	/**
	 * Dump the routes and nonces.
	 *
	 * @return array[]
	 */
	public function dump_routes_and_nonces() {
		$nonces = array();
		$routes = array();
		foreach ( $this->get_methods() as $method ) {
			$doc_block = $method->getDocComment();
			if ( stristr( $doc_block, '@defender_route' ) ) {
				if ( 'register_routes' === $method->getName() ) {
					continue;
				}
				$nonces[ $method->getName() ] = wd_central()->get_nonce( $method->getName(), static::class );
				$routes[ $method->getName() ] = wd_central()->get_route( $method->getName(), static::class );
			}
		}

		return array(
			'routes' => $routes,
			'nonces' => $nonces,
		);
	}

	/**
	 * Check if DEFENDER_DEBUG is enabled for the route.
	 *
	 * @param  string $route  Route to check.
	 *
	 * @return string|array
	 */
	public function check_route( string $route ) {
		return defined( 'DEFENDER_DEBUG' ) && true === constant( 'DEFENDER_DEBUG' )
			? wp_slash( $route )
			: $route;
	}

	/**
	 * Shared data for all controllers (profile, hub connector, isPro, etc.).
	 *
	 * @return array
	 */
	protected function get_shared_data(): array {
		$hub_profile_ui = Hub_Connector::get_profile_data_for_ui();
		$profile_data   = is_array( $hub_profile_ui ) ? $hub_profile_ui : array();
		$wpmudev        = wd_di()->get( \WP_Defender\Behavior\WPMUDEV::class );
		$scan_api       = wd_di()->get( \WP_Defender\Controller\Scan::class )->dump_routes_and_nonces();

		return array(
			'defenderUrl'        => network_admin_url( 'admin.php?page=wp-defender' ),
			'pluginUrl'          => WP_DEFENDER_BASE_URL,
			'adminUrl'           => network_admin_url(),
			'siteUrl'            => network_site_url(),
			'profileData'        => $profile_data,
			'hubConnector'       => wd_di()->get( \WP_Defender\Controller\Hub_Connector::class )->data_frontend(),
			'isPro'              => $wpmudev->is_pro(),
			'isWpOrg'            => defender_is_wp_org_version(),
			'pluginUpdate'       => $this->get_plugin_update_notice_data(),
			'whiteLabel'         => defender_whitelabel_data(),
			'activityLog'        => wd_di()->get( \WP_Defender\Controller\Activity_Log::class )->data_frontend(),
			'hubApiKey'          => array(
				'available' => false !== $wpmudev->get_apikey(),
			),
			'hosted'             => $wpmudev->is_wpmu_hosting(),
			'highContrastMode'   => defender_high_contrast(),
			'isUnlimitedHosting' => defender_is_unlimited_hosting(),
			'scanApi'            => array(
				'routes' => $scan_api['routes'] ?? array(),
				'nonces' => $scan_api['nonces'] ?? array(),
			),
		);
	}

	/**
	 * Page-specific data for a concrete controller.
	 *
	 * @return array
	 */
	protected function get_page_data(): array {
		return array();
	}
}
