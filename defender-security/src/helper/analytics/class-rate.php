<?php
/**
 * Responsible for gathering analytics data for the rating functionality.
 *
 * @package WP_Defender\Helper\Analytics
 */

namespace WP_Defender\Helper\Analytics;

use WP_Defender\Event;
use WP_Defender\Component\Rate as Rate_Component;

/**
 * Gather analytics data required for rating functionality.
 */
class Rate extends Event {

	public const EVENT_ARCHIEVEMENT_REVIEW_PROMPT = 'Rating Notice';

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
	 * @param array $data Data to be imported into the model.
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
	 * @return array
	 */
	public function export_strings() {
		return array();
	}

	/**
	 * Track feature.
	 *
	 * @param string $notice_slug  Notice slug.
	 * @param string $action       CTA clicked.
	 * @param string $location     Page showing the notice.
	 *
	 * @return void
	 */
	public function track_rating( string $notice_slug, string $action, string $location ) {
		$prompt = Rate_Component::get_label_by_slug( $notice_slug );
		if ( '' !== $prompt && '' !== $location ) {
			$this->track_feature(
				self::EVENT_ARCHIEVEMENT_REVIEW_PROMPT,
				array(
					'Action'      => $action,
					'Notice Type' => $prompt,
					'Location'    => $location,
				)
			);
		}
	}
}
