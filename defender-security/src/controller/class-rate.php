<?php
/**
 * Handle rating functionality.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Event;
use Calotes\Component\Response;
use Calotes\Component\Request;
use WP_Defender\Component\Rate as Rate_Component;
use WP_Defender\Helper\Analytics\Rate as Rate_Analytics;

/**
 * Handle rating functionality.
 *
 * @since 5.6.0
 */
class Rate extends Event {

	/**
	 * Initialize the class by setting button labels and registering actions.
	 */
	public function __construct() {
		$this->register_routes();
	}

	/**
	 * Handle notice.
	 *
	 * @param Request $request Request object.
	 *
	 * @return Response Response object.
	 * @defender_route
	 */
	public function handle_notice( Request $request ): Response {
		Rate_Component::reset_counters();
		update_site_option( Rate_Component::SLUG_FOR_BUTTON_RATE, true );
		// Track.
		$data = $request->get_data(
			array(
				'prompt'   => array( 'type' => 'string' ),
				'location' => array( 'type' => 'string' ),
			)
		);
		wd_di()->get( Rate_Analytics::class )->track_rating( $data['prompt'], 'rate', $data['location'] );

		return new Response( true, array() );
	}

	/**
	 * Handle postponed notice.
	 * Reset counters and set new date to display a postponed notice.
	 *
	 * @param Request $request Request object.
	 *
	 * @return Response Response object.
	 * @defender_route
	 */
	public function postpone_notice( Request $request ): Response {
		Rate_Component::reset_counters();
		update_site_option( Rate_Component::SLUG_POSTPONED_NOTICE_DATE, time() );
		// Track.
		$data = $request->get_data(
			array(
				'prompt'   => array( 'type' => 'string' ),
				'location' => array( 'type' => 'string' ),
			)
		);
		wd_di()->get( Rate_Analytics::class )->track_rating( $data['prompt'], 'remind_later', $data['location'] );

		return new Response( true, array() );
	}

	/**
	 * Handle refuse notice.
	 *
	 * @param Request $request Request object.
	 *
	 * @return Response Response object.
	 * @defender_route
	 */
	public function refuse_notice( Request $request ): Response {
		Rate_Component::reset_counters();
		update_site_option( Rate_Component::SLUG_FOR_BUTTON_THANKS, true );
		// Track.
		$data = $request->get_data(
			array(
				'prompt'   => array( 'type' => 'string' ),
				'location' => array( 'type' => 'string' ),
			)
		);
		wd_di()->get( Rate_Analytics::class )->track_rating( $data['prompt'], 'dismiss', $data['location'] );

		return new Response( true, array() );
	}

	/**
	 * All the variables that we will show on frontend.
	 *
	 * @return array
	 */
	public function data_frontend() {
		return array_merge(
			array(
				'repo_link'       => Rate_Component::URL_PLUGIN_NEW_REVIEW_VCS,
				'rate_button'     => Rate_Component::get_rate_button_title(),
				'dismiss_button'  => Rate_Component::get_dismiss_button_title(),
				'postpone_button' => Rate_Component::get_postpone_button_title(),
				'location'        => Rate_Component::get_current_page_label(),
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Delete all the data.
	 */
	public function remove_data() {
		delete_site_option( Rate_Component::SLUG_COMPLETED_SCANS );
		delete_site_option( Rate_Component::SLUG_FIXED_SCAN_ISSUES );
		delete_site_option( Rate_Component::SLUG_FREE_INSTALL_DATE );
		delete_site_option( Rate_Component::SLUG_FOR_BUTTON_RATE );
		delete_site_option( Rate_Component::SLUG_FOR_BUTTON_THANKS );
		delete_site_option( Rate_Component::SLUG_POSTPONED_NOTICE_DATE );
		delete_site_option( Rate_Component::SLUG_UA_LOCKOUTS );
		delete_site_option( Rate_Component::SLUG_IP_LOCKOUTS );
	}

	/**
	 * Export strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		return array();
	}

	/**
	 * Convert the object data to an array.
	 *
	 * @return array An array representation of the object.
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Import data into the model.
	 *
	 * @param  array $data  Data to be imported into the model.
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Remove settings for all submodules.
	 */
	public function remove_settings(): void {
	}
}
