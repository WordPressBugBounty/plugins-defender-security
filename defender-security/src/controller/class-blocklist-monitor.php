<?php
/**
 * Manages the block list monitoring functionality for domains.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Error;
use WP_Defender\Controller;
use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Behavior\WPMUDEV;

/**
 * Manages the block list monitoring functionality for domains.
 */
class Blocklist_Monitor extends Controller {

	public const CACHE_BLACKLIST_STATUS = 'wpdefender_blacklist_status', CACHE_TIME = 300;

	public const MODULE_SLUG = 'blocklist-monitor';

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 */
	public function __construct() {
		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
		$this->register_routes();
		// admin_init priority 20 runs after Hub_Connector sets the transient (priority 10);
		// the other two hooks cover async-sync cases.
		add_action( 'admin_init', array( $this, 'maybe_hcm_connection_attempt' ), 20 );
		add_action( 'wpdef_hub_connector_synced', array( $this, 'maybe_hcm_connection_attempt' ) );
		add_action( 'wpmudev_hub_connector_first_sync_completed', array( $this, 'maybe_hcm_connection_attempt' ) );
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
	 * Removes settings for all submodules.
	 */
	public function remove_settings() {
		$this->reset_blocklist_monitor();
		delete_site_transient( self::CACHE_BLACKLIST_STATUS );
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
	}

	/**
	 * All the variables that we will show on frontend, both in the main page, or dashboard widget.
	 *
	 * @return array
	 */
	public function data_frontend() {
		$available = false !== $this->get_apikey();
		$status    = get_site_transient( self::CACHE_BLACKLIST_STATUS );

		return array_merge(
			$this->dump_routes_and_nonces(),
			array(
				'status' => $available && false !== $status && ! is_wp_error( $status ) ? $status : -1,
			)
		);
	}

	/**
	 * Imports data into the model.
	 *
	 * @param  array $data  Data to be imported into the model.
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Resets the block list monitor by making a DELETE request to the WPMUDEV API.
	 *
	 * @return mixed The response from the WPMUDEV API.
	 */
	private function reset_blocklist_monitor() {
		return $this->make_wpmu_request( WPMUDEV::API_BLACKLIST, array(), array( 'method' => 'DELETE' ) );
	}

	/**
	 * Getting domain status.
	 *
	 * @return int|WP_Error
	 */
	protected function domain_status() {
		$response = $this->make_wpmu_request( WPMUDEV::API_BLACKLIST );

		if ( is_wp_error( $response ) ) {
			if ( 412 === $response->get_error_code() ) {
				return - 1;
			}

			return $response;
		}
		$status = 1;
		foreach ( $response['services'] as $service ) {
			if ( true === $service['blacklisted'] ) {
				$status = 0;
			}
		}

		return $status;
	}

	/**
	 * Endpoint for getting domain status.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function blacklist_status(): Response {
		$status = get_site_transient( self::CACHE_BLACKLIST_STATUS );
		if ( false === $status ) {
			$status = $this->domain_status();
			set_site_transient( self::CACHE_BLACKLIST_STATUS, $status, self::CACHE_TIME );
		}

		if ( is_wp_error( $status ) ) {
			return new Response(
				false,
				array(
					'status_error' => $status->get_error_message(),
				)
			);
		}

		return new Response( true, array( 'status' => $status ) );
	}

	/**
	 * Toggles the domain's block list status based on the provided status.
	 *
	 * @param  Request $request  The request object containing the new status.
	 *
	 * @return bool|Response True on success, or Response object on failure.
	 * @defender_route
	 */
	public function toggle_blacklist_status( Request $request ) {
		$data           = $request->get_data(
			array(
				'status' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		$current_status = $data['status'] ?? null;
		if ( ! in_array( $current_status, array( 'good', 'new', 'blacklisted' ), true ) ) {
			return false;
		}

		if ( false === $this->get_apikey() ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'A WPMU DEV subscription is required for blocklist monitoring.', 'defender-security' ),
				)
			);
		}
		if ( 'new' === $current_status ) {
			$this->make_wpmu_request( WPMUDEV::API_BLACKLIST, array(), array( 'method' => 'POST' ) );
			$status = $this->domain_status();
		} else {
			$this->reset_blocklist_monitor();
			$status = - 1;
		}
		set_site_transient( self::CACHE_BLACKLIST_STATUS, $status, self::CACHE_TIME );

		return new Response( true, array( 'status' => $status ) );
	}

	/**
	 * Changes the domain's block list status if it differs from the current status.
	 *
	 * @param  string $current_status  The current status to compare against.
	 *
	 * @return void
	 */
	public function change_status( $current_status ): void {
		$status = get_site_transient( self::CACHE_BLACKLIST_STATUS );
		if ( false === $status ) {
			$status = $this->domain_status();
		}
		// Check changes.
		if ( $status !== $current_status ) {
			if ( '1' === $current_status ) {
				$this->make_wpmu_request( WPMUDEV::API_BLACKLIST, array(), array( 'method' => 'POST' ) );
				$status = $this->domain_status();
			} else {
				$this->reset_blocklist_monitor();
				$status = - 1;
			}
			set_site_transient( self::CACHE_BLACKLIST_STATUS, $status, self::CACHE_TIME );
		}
	}

	/**
	 * Get domain status. Variants:
	 * '1' -> 'good'
	 */
	public function get_status() {
		$status = get_site_transient( self::CACHE_BLACKLIST_STATUS );
		if ( false === $status ) {
			$status = $this->domain_status();
		}

		if ( is_wp_error( $status ) ) {
			return $status->get_error_message();
		}

		return $status;
	}

	/**
	 * Auto-enable blocklist monitoring after Hub connection if user triggered from Settings/Tools page.
	 *
	 * @return void
	 */
	public function maybe_hcm_connection_attempt(): void {
		$data        = get_site_transient( Hub_Connector::TRANSIENT_KEY );
		$module_slug = $data['module_slug'] ?? '';

		if ( self::MODULE_SLUG !== $module_slug || ! self::get_hcm_status() ) {
			return;
		}

		delete_site_transient( Hub_Connector::TRANSIENT_KEY );

		$this->make_wpmu_request( WPMUDEV::API_BLACKLIST, array(), array( 'method' => 'POST' ) );
		$status = $this->domain_status();
		set_site_transient( self::CACHE_BLACKLIST_STATUS, $status, self::CACHE_TIME );
	}

	/**
	 * Exports strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		if ( false === $this->get_apikey() ) {
			return array( esc_html__( 'Blocklist Monitor inactive', 'defender-security' ) );
		}

		if ( '1' === (string) $this->get_status() ) {
			$strings = array( esc_html__( 'Blocklist Monitor active', 'defender-security' ) );
		} else {
			$strings = array( esc_html__( 'Blocklist Monitor inactive', 'defender-security' ) );
		}

		return $strings;
	}

	/**
	 * Configures strings based on the provided configuration
	 *
	 * @param  array $config  Configuration array.
	 *
	 * @return array An array of configuration strings.
	 */
	public function config_strings( array $config ): array {
		if ( false === $this->get_apikey() ) {
			return array( esc_html__( 'Blocklist Monitor inactive', 'defender-security' ) );
		}

		return $config['enabled'] ? array( esc_html__( 'Blocklist Monitor active', 'defender-security' ) ) : array(
			esc_html__( 'Blocklist Monitor inactive', 'defender-security' ),
		);
	}

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return array(
			'enabled' => esc_html__( 'Blocklist Monitor', 'defender-security' ),
			'status'  => esc_html__( 'Status', 'defender-security' ),
		);
	}
}
