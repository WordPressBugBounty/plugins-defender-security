<?php
/**
 * Handles data tracking functionalities.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use Exception;
use WP_Defender\Event;
use Calotes\Component\Response;
use WP_Defender\Model\Setting\Main_Setting;
use WP_Defender\Component\Config\Config_Hub_Helper;

/**
 * Handles data tracking functionalities.
 *
 * @since 4.2.0
 */
class Data_Tracking extends Event {

	public const TRACKING_SLUG = 'wd_show_usage_data';

	/**
	 * Site option key that controls the dashboard share-usage bubble lifecycle.
	 * Kept separate from TRACKING_SLUG so that skipping onboarding does not
	 * suppress the bubble.
	 */
	public const DASHBOARD_NOTICE_SLUG = 'wd_show_dashboard_usage_notice';

	/**
	 * Records whether the dashboard notice lifecycle has been initialized.
	 */
	public const DASHBOARD_NOTICE_INITIALIZED_SLUG = 'wd_dashboard_usage_notice_initialized';

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 */
	public function __construct() {
		$this->register_routes();
	}

	/**
	 * Handles the closing of the tracking modal.
	 *
	 * @return Response Response object indicating success.
	 * @defender_route
	 */
	public function close_track_modal(): Response {
		$model_settings = wd_di()->get( Main_Setting::class );

		if ( true === $model_settings->usage_tracking ) {
			$model_settings->toggle_tracking( false );
			Config_Hub_Helper::set_clear_active_flag();
			$this->track_opt_toggle( false, 'Tracking modal' );
		}
		// Track.
		$this->track_feature( 'def_tracking_modal', array( 'Modal Action' => 'closed' ) );
		self::dismiss_modal_key();

		return new Response( true, array() );
	}

	/**
	 * Save Enabled tracking state.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_track_modal(): Response {
		$model_settings = wd_di()->get( Main_Setting::class );
		// Update the value if it's changed.
		if ( true !== $model_settings->usage_tracking ) {
			$model_settings->toggle_tracking( true );
			// Changes for Hub.
			Config_Hub_Helper::set_clear_active_flag();
			// Track#1.
			$this->track_opt_toggle( true, 'Tracking modal' );
			// Track#2.
			$this->track_feature( 'def_tracking_modal', array( 'Modal Action' => 'cta_clicked' ) );
		}
		// Hide the modal.
		self::dismiss_modal_key();

		return new Response( true, array() );
	}

	/**
	 * Marks the tracking notice as dismissed without resetting initialization state.
	 *
	 * @return void
	 */
	public static function dismiss_modal_key(): void {
		update_site_option( self::TRACKING_SLUG, false );
	}

	/**
	 * Deletes the site option that controls the visibility of the tracking modal.
	 */
	public static function delete_modal_key(): void {
		delete_site_option( self::TRACKING_SLUG );
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
		self::delete_modal_key();
		delete_site_option( self::DASHBOARD_NOTICE_SLUG );
		delete_site_option( self::DASHBOARD_NOTICE_INITIALIZED_SLUG );
	}

	/**
	 * Exports strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		return array();
	}

	/**
	 * Converts the object data to an array.
	 *
	 * @return array An array representation of the object.
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Imports data into the model.
	 *
	 * @param  array $data  Data to be imported into the model.
	 *
	 * @throws Exception If table is not defined.
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings(): void {
		self::delete_modal_key();
		delete_site_option( self::DASHBOARD_NOTICE_SLUG );
		delete_site_option( self::DASHBOARD_NOTICE_INITIALIZED_SLUG );
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		return array();
	}

	/**
	 * Initializes the dashboard notice lifecycle once.
	 *
	 * A dedicated marker distinguishes an intentionally consumed false value
	 * from an option that an older or interrupted upgrade failed to seed.
	 *
	 * @return void
	 */
	public static function initialize_dashboard_notice(): void {
		if ( (bool) get_site_option( self::DASHBOARD_NOTICE_INITIALIZED_SLUG ) ) {
			return;
		}

		$usage_tracking = wd_di()->get( Main_Setting::class )->usage_tracking;
		delete_site_option( self::DASHBOARD_NOTICE_SLUG );
		add_site_option( self::DASHBOARD_NOTICE_SLUG, ! $usage_tracking );
		update_site_option( self::DASHBOARD_NOTICE_INITIALIZED_SLUG, true );
	}

	/**
	 * Returns whether the dashboard share usage notice should be displayed.
	 *
	 * @return bool
	 */
	public function should_show_dashboard_notice(): bool {
		$notice_option = (bool) get_site_option( self::DASHBOARD_NOTICE_SLUG );

		// Falsey means not eligible or already displayed.
		if ( ! $notice_option ) {
			return false;
		}

		// Truthy means eligible; also guard against already opted-in.
		return ! wd_di()->get( Main_Setting::class )->usage_tracking;
	}

	/**
	 * Returns dashboard notice data and routes for the share usage bubble.
	 *
	 * @return array
	 */
	public function get_dashboard_notice_data(): array {
		self::initialize_dashboard_notice();
		$result = $this->dump_routes_and_nonces();

		return array(
			'shareUsageNotice' => array(
				'isVisible' => $this->should_show_dashboard_notice(),
			),
			'routes'           => $result['routes'],
			'nonces'           => $result['nonces'],
		);
	}

	/**
	 * Marks the share usage dashboard notice as already shown.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function mark_track_notice_displayed(): Response {
		update_site_option( self::DASHBOARD_NOTICE_SLUG, false );

		return new Response( true, array() );
	}
}
