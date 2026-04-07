<?php
/**
 * Handles all service related actions.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Controller;

/**
 * Contains methods for handling scans.
 */
class Expert_Services extends Controller {

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	public $slug = 'wdf-expert-services';

	/**
	 * Initializes the model and service, registers routes.
	 */
	public function __construct() {
	}

	/**
	 * Enqueues scripts and styles for this page.
	 * Only enqueues assets if the page is active.
	 */
	public function enqueue_assets(): void {
		if ( $this->is_page_active() ) {
			wp_enqueue_script( 'def-expert-services' );
			$this->enqueue_main_assets();
		}
	}

	/**
	 * All the variables that we will show on frontend, both in the main page, or dashboard widget.
	 *
	 * @return array
	 */
	public function data_frontend() {
		return array();
	}

	/**
	 * Export the data of this module, we will use this for export to HUB, create a preset etc.
	 *
	 * @return array
	 */
	public function to_array() {
		return array();
	}

	/**
	 * Import the data of other source into this, it can be when HUB trigger the import, or user apply a preset.
	 *
	 * @param array $data Data from other source.
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Remove all settings, configs generated in this container runtime.
	 */
	public function remove_settings() {
	}

	/**
	 * Remove all data.
	 */
	public function remove_data() {
	}

	/**
	 * Export strings.
	 *
	 * @return array
	 */
	public function export_strings(): array {
		return array();
	}

	/**
	 * Render the page.
	 *
	 * @return void
	 */
	public function main_view(): void {
		$this->render( 'main' );
	}
}
