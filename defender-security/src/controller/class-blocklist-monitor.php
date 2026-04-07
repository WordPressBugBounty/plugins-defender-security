<?php
/**
 * Handle Blocklist Monitor module for free version.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use Calotes\Component\Response;
use WP_Defender\Controller;

/**
 * Handle Blocklist Monitor module for free version.
 */
class Blocklist_Monitor extends Controller {

	/**
	 * Initializes routes for compatibility with existing frontend calls.
	 */
	public function __construct() {
		$this->register_routes();
	}

	/**
	 * Converts the current object state to an array.
	 *
	 * @return array
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings() {
	}

	/**
	 * Delete all the data and the cache.
	 */
	public function remove_data() {
	}

	/**
	 * Returns frontend payload.
	 *
	 * @return array
	 */
	public function data_frontend() {
		return $this->dump_routes_and_nonces();
	}

	/**
	 * Imports data into the model.
	 *
	 * @param array $data Data to import.
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Endpoint for getting domain status.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function blacklist_status(): Response {
		return new Response( true, array( 'status' => -1 ) );
	}

	/**
	 * Endpoint for toggling domain status.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function toggle_blacklist_status(): Response {
		return new Response(
			false,
			array(
				'message' => esc_html__( 'A WPMU DEV subscription is required for blocklist monitoring.', 'defender-security' ),
			)
		);
	}

	/**
	 * Keeps compatibility with config import flow.
	 *
	 * @param string $current_status Current status.
	 */
	public function change_status( $current_status ): void {
	}

	/**
	 * Returns a disabled status in free version.
	 *
	 * @return int
	 */
	public function get_status() {
		return -1;
	}

	/**
	 * Exports strings.
	 *
	 * @return array
	 */
	public function export_strings(): array {
		return array(
			sprintf(
			/* translators: %s: Html for Pro-tag. */
				esc_html__( 'Inactive %s', 'defender-security' ),
				'<span class="sui-tag sui-tag-pro">Pro</span>'
			),
		);
	}

	/**
	 * Config strings.
	 *
	 * @param array $config Configuration array.
	 *
	 * @return array
	 */
	public function config_strings( $config ): array {
		return $this->export_strings();
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
