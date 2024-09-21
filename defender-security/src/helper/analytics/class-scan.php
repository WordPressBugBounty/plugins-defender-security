<?php
/**
 * Responsible for gathering analytics data for the scan feature.
 *
 * @package WP_Defender\Helper\Analytics
 */

namespace WP_Defender\Helper\Analytics;

use WP_Defender\Event;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Model\Scan as Scan_Model;
use WP_Defender\Model\Setting\Scan as Scan_Setting;

/**
 * Gather analytics data required for scan feature.
 */
class Scan extends Event {

	public const EVENT_SCAN_FAILED        = 'def_scan_failed_new';
	public const EVENT_SCAN_FAILED_PROP   = 'Failure reason';
	public const EVENT_SCAN_FAILED_CANCEL = 'User Cancellation';
	public const EVENT_SCAN_FAILED_ERROR  = 'Error';

	// Mandatory empty methods.
	// Start.
	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		return array();
	}

	/**
	 * Converts the current state of the object to an array.
	 *
	 * @return array Returns an associative array of object properties.
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
	 * Removes settings for all submodules.
	 */
	public function remove_settings() {
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
	}

	/**
	 * Exports strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		return array();
	}
	// End.

	/**
	 * Analytics data for scan started event.
	 *
	 * @param  Scan_Setting $scan_setting  Scan settings object.
	 *
	 * @return array[
	 *   'event' => string,
	 *   'data' => array
	 * ]
	 */
	public function scan_started( Scan_Setting $scan_setting ): array {
		$analytics_data = array(
			'Core File change'      => 'Disabled',
			'Plugin file change'    => 'Disabled',
			'Known Vulnerabilities' => 'Disabled',
			'Suspicious Code'       => 'Disabled',
		);

		if ( $scan_setting->integrity_check && $scan_setting->check_core ) {
			$analytics_data['Core File change'] = 'Enabled';
		}

		if ( $scan_setting->integrity_check && $scan_setting->check_plugins ) {
			$analytics_data['Plugin file change'] = 'Enabled';
		}

		$is_pro = wd_di()->get( WPMUDEV::class )->is_pro();

		if ( $is_pro && $scan_setting->check_known_vuln ) {
			$analytics_data['Known Vulnerabilities'] = 'Enabled';
		}

		if ( $is_pro && $scan_setting->scan_malware ) {
			$analytics_data['Suspicious Code'] = 'Enabled';
		}

		return array(
			'event' => 'def_scan_started',
			'data'  => $analytics_data,
		);
	}

	/**
	 * Analytics data for scan completed event.
	 *
	 * @param  Scan_Model $scan_model  Scan model object.
	 *
	 * @return array[
	 *   'event' => string,
	 *   'data' => array
	 * ]
	 */
	public function scan_completed( Scan_Model $scan_model ): array {
		$last_scan             = $scan_model::get_last();
		$scan_item_group_total = wd_di()->get( Scan_Item::class )
										->get_types_total( $last_scan->id, Scan_Item::STATUS_ACTIVE );

		$data = array();

		if ( isset( $scan_item_group_total['all'] ) ) {
			$data['Threats Count'] = $scan_item_group_total['all'];
		}

		if ( isset( $scan_item_group_total['core_integrity'] ) ) {
			$data['WP core issue count'] = $scan_item_group_total['core_integrity'];
		}

		if ( isset( $scan_item_group_total['malware'] ) ) {
			$data['Suspicious Code'] = $scan_item_group_total['malware'];
		}

		if ( isset( $scan_item_group_total['plugin_integrity'] ) ) {
			$data['Plugin file modified'] = $scan_item_group_total['plugin_integrity'];
		}

		if ( isset( $scan_item_group_total['vulnerability'] ) ) {
			$data['Vulnerability'] = $scan_item_group_total['vulnerability'];
		}

		return array(
			'event' => 'def_scan_completed_new',
			'data'  => $data,
		);
	}
}
