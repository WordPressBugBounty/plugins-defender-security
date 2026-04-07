<?php
/**
 * Handles malicious bot functionality (Free version stub).
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Controller;

/**
 * Stub class for malicious bot functionality in the Free version.
 * This feature is only available in the Pro version.
 */
class Malicious_Bot extends Controller {

	/**
	 * Constructor for the Malicious_Bot class.
	 * Does nothing in the Free version.
	 *
	 * @param mixed $service Unused in Free version.
	 */
	public function __construct( $service = null ) {
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
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings(): void {
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		return array();
	}
}
