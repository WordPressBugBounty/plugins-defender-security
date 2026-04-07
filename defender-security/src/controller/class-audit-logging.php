<?php
/**
 * Handle Audit Logging module.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Event;
use Calotes\Component\Response;
use WP_Defender\Model\Setting\Audit_Logging as Model_Audit_Logging;

/**
 * Handle Audit Logging module.
 */
class Audit_Logging extends Event {

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	public $slug = 'wdf-logging';

	/**
	 * The model for handling the data.
	 *
	 * @var Model_Audit_Logging
	 */
	public $model;

	/**
	 * Initializes the model, registers the menu page and routes.
	 */
	public function __construct() {
		$this->register_page(
			esc_html( Model_Audit_Logging::get_module_name() ),
			$this->slug,
			array( $this, 'main_view' ),
			$this->parent_slug
		);
		add_action( 'defender_enqueue_assets', array( $this, 'enqueue_assets' ) );
		$this->model = wd_di()->get( Model_Audit_Logging::class );
		$this->register_routes();
	}

	/**
	 * Enqueues scripts and styles for this page.
	 */
	public function enqueue_assets(): void {
		if ( ! $this->is_page_active() ) {
			return;
		}
		wp_localize_script( 'def-audit', 'audit', $this->data_frontend() );
		wp_enqueue_script( 'def-audit' );
		$this->enqueue_main_assets();
	}

	/**
	 * Render the root element for frontend.
	 */
	public function main_view(): void {
		$this->render( 'main' );
	}

	/**
	 * Dummy — returns empty logs response.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function pull_logs(): Response {
		return new Response( false, array() );
	}

	/**
	 * Dummy — no-op CSV export.
	 *
	 * @defender_route
	 */
	public function export_as_csv(): void {
	}

	/**
	 * Dummy — returns empty summary.
	 *
	 * @defender_route
	 */
	public function summary(): void {
		wp_send_json_success( array() );
	}

	/**
	 * Dummy — returns empty summary data.
	 *
	 * @param bool $for_hub Default false.
	 *
	 * @return array
	 */
	public function summary_data( bool $for_hub = false ): array {
		return array();
	}

	/**
	 * Dummy — save settings no-op.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_settings(): Response {
		return new Response( true, array() );
	}

	/**
	 * All the variables that we will show on frontend.
	 *
	 * @return array
	 */
	public function data_frontend(): array {
		return array();
	}

	/**
	 * Converts the current state of the object to an array.
	 *
	 * @return array
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Dummy — import data no-op.
	 *
	 * @param array $data Data to import.
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Remove all settings.
	 */
	public function remove_settings(): void {
	}

	/**
	 * Dummy — remove data no-op.
	 */
	public function remove_data(): void {
	}

	/**
	 * Export strings.
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
	 * Config strings — always returns inactive.
	 *
	 * @param array $config Configuration data.
	 *
	 * @return array
	 */
	public function config_strings( array $config ): array {
		return $this->export_strings();
	}
}
