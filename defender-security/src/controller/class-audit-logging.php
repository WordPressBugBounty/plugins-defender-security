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
			esc_html__( 'Audit Log', 'defender-security' ),
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

		$handle = 'defender-ui-audit-logging';
		wp_enqueue_script(
			$handle,
			WP_DEFENDER_BASE_URL . 'assets/js/audit-logging-ui.js',
			array( 'def-vue', 'def-manifest', 'def-core-ui', 'defender', 'wp-i18n' ),
			DEFENDER_VERSION,
			true
		);

		wp_localize_script(
			$handle,
			'defenderUIData',
			array_merge(
				$this->get_shared_data(),
				$this->data_frontend()
			)
		);

		wp_enqueue_style(
			$handle,
			WP_DEFENDER_BASE_URL . 'assets/css/showcase.css',
			array(),
			DEFENDER_VERSION
		);

		$this->enqueue_main_assets();
	}

	/**
	 * Render the root element for frontend.
	 *
	 * @return void
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
		return array(
			'auditLogging' => array_merge(
				array(
					'model'       => $this->model->export(),
					'logs'        => array(),
					'events_type' => array(),
					'summary'     => array(
						'count_7_days' => 0,
						'report'       => '',
					),
					'paging'      => array(
						'paged'       => 1,
						'total_pages' => 1,
						'count'       => 0,
					),
				),
				$this->dump_routes_and_nonces()
			),
			'antibot'      => wd_di()->get( \WP_Defender\Controller\Antibot_Global_Firewall::class )->data_frontend(),
		);
	}

	/**
	 * Converts the current state of the object to an array.
	 *
	 * @return array
	 */
	public function to_array(): array {
		return array_merge(
			array(
				'enabled' => false,
				'report'  => false,
			),
			$this->dump_routes_and_nonces()
		);
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
