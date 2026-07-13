<?php
/**
 * Handles Web Application Firewall related functionality.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Controller;
use Calotes\Component\Response;
use WP_Defender\Behavior\WPMUDEV;

/**
 * Handles the settings, data, and other functionality related to the Web Application Firewall (WAF).
 */
class WAF extends Controller {
	/**
	 * Option key storing the last known WAF status for change detection.
	 */
	private const LAST_STATUS_OPTION = 'defender_waf_last_known_status';

	/**
	 * Transient key set for 5 minutes when WAF status changes, used to drive the sync notice.
	 */
	private const STATUS_CHANGED_TRANSIENT = 'defender_waf_status_changed';

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	public $slug = 'wdf-waf';
	/**
	 * The WPMUDEV instance used for interacting with WPMUDEV services.
	 *
	 * @var WPMUDEV
	 */
	private $wpmudev;

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 */
	public function __construct() {
		$this->wpmudev = wd_di()->get( WPMUDEV::class );
		$this->register_routes();
	}

	/**
	 * Remove the cache and return latest data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function recheck(): Response {
		return new Response( true, array( 'waf' => $this->data_frontend() ) );
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
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
		delete_option( self::LAST_STATUS_OPTION );
		delete_transient( self::STATUS_CHANGED_TRANSIENT );
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		$current_status = $this->get_waf_status();
		return array(
			'site_id'          => $this->wpmudev->get_site_id(),
			'status'           => $current_status,
			'show_sync_notice' => $this->get_show_sync_notice( $current_status ),
		);
	}

	/**
	 * Retrieves the WAF status for a given site.
	 *
	 * @return bool Returns false on failure, true if WAF is enabled.
	 */
	public function get_waf_status(): bool {
		$status = defender_get_hosting_feature_state( 'waf' );
		return '' !== $status && true === (bool) $status;
	}

	/**
	 * Detects whether WAF status has recently changed and returns whether the sync notice should be shown.
	 *
	 * Sets a 5-minute transient on first detection of a status change so the notice persists across page loads.
	 *
	 * @param  bool $current_status  Current WAF enabled/disabled state.
	 * @return bool True if the sync notice should be displayed.
	 */
	private function get_show_sync_notice( bool $current_status ): bool {
		$stored = get_option( self::LAST_STATUS_OPTION, null );

		if ( null === $stored ) {
			update_option( self::LAST_STATUS_OPTION, $current_status );
			return false;
		}

		if ( (bool) $stored !== $current_status ) {
			update_option( self::LAST_STATUS_OPTION, $current_status );
			set_transient( self::STATUS_CHANGED_TRANSIENT, true, 5 * MINUTE_IN_SECONDS );
			return true;
		}

		return (bool) get_transient( self::STATUS_CHANGED_TRANSIENT );
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
		return array(
			sprintf(
				/* translators: %s: Html for Pro-tag. */
				esc_html__( 'Inactive %s', 'defender-security' ),
				'<span class="sui-tag sui-tag-pro">Pro</span>'
			),
		);
	}
}
