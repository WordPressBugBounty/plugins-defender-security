<?php
/**
 * Handle session protection module.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Controller;
use Calotes\Component\Response;
use WP_Defender\Model\Setting\Session_Protection as Settings;

/**
 * Handle session protection module.
 */
class Session_Protection extends Controller {

	/**
	 * The model for the session protection module.
	 *
	 * @var Settings|null
	 */
	protected ?Settings $model = null;

	/**
	 * Initializes the model, registers routes.
	 */
	public function __construct() {
		$this->model   = wd_di()->get( Settings::class );
		add_filter( 'wp_defender_advanced_tools_data', array( $this, 'script_data' ) );
		$this->register_routes();
	}

	/**
	 * Provide data to the frontend via localized script.
	 *
	 * @param array $data Data collection is ready to passed.
	 *
	 * @return array Modified data array with added this controller data.
	 */
	public function script_data( array $data ): array {
		$data['session_protection'] = $this->data_frontend();

		return $data;
	}

	/**
	 * All the variables that we will show on frontend, both in the main page, or dashboard widget.
	 *
	 * @return array
	 */
	public function data_frontend(): array {
		return array_merge(
			array(
				'model'      => $this->model->export(),
				'properties' => array(),
				'roles'      => array(),
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Save settings.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_settings(): Response {
		return new Response( true, array() );
	}

	/**
	 * Dummy.
	 *
	 * @return array
	 */
	public function to_array() {
		return array();
	}

	/**
	 * Dummy.
	 *
	 * @param array $data The data to import.
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
	public function export_strings() {
		return array(
			esc_html__( 'Inactive', 'defender-security' ),
		);
	}

	/**
	 * Provides data for the dashboard widget.
	 *
	 * @return array An array of dashboard widget data.
	 */
	public function dashboard_widget(): array {
		return array( 'model' => $this->model->export() );
	}
}
