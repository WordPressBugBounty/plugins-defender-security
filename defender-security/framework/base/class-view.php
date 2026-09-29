<?php
/**
 * Base view class.
 *
 * @package Calotes\Base
 */

namespace Calotes\Base;

/**
 * Base class for all views.
 */
class View extends Component {


	/**
	 * Holds the blocks used in the view.
	 *
	 * @var array
	 */
	public $blocks = array();

	/**
	 * Holds parameters that can be passed to the view.
	 *
	 * @var array
	 */
	public $params = array();

	/**
	 * The template file in which this view should be rendered.
	 *
	 * @var null
	 */
	public $layout = null;

	/**
	 * The file contains content of this view, relative path.
	 *
	 * @var null
	 */
	public $view_file = null;

	/**
	 * The folder contains view files, absolute path.
	 *
	 * @var null
	 */
	private $base_path = null;

	/**
	 * Constructor to set the base path of the view.
	 *
	 * @param mixed $base_path The base path of the view.
	 */
	public function __construct( $base_path ) {
		$this->base_path = $base_path;
	}

	/**
	 * Render a view file. This will be used to render a whole page.
	 * If a layout is defined, then we will render layout + view.
	 *
	 * @param string $view   The name of the view file to render.
	 * @param array  $params An optional array of parameters to pass to the view file.
	 *
	 * @return string
	 */
	public function render( $view, $params = array() ) {
		$view_file = $this->base_path . DIRECTORY_SEPARATOR . $view . '.php';
		$real_base = realpath( $this->base_path );
		$real_file = realpath( $view_file );

		if ( false !== $real_base && false !== $real_file && str_starts_with(
			$real_file,
			rtrim( $real_base, DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR
		) && is_file( $real_file )
		) {
			return $this->render_php_file( $real_file, $params );
		}

		return '';
	}

	/**
	 * Renders a PHP file and returns its output.
	 *
	 * @param string $_view_file_path_ The path to the PHP file to render.
	 * @param array  $params           An optional array of parameters to pass to the PHP file.
	 *
	 * @return string The output of the rendered PHP file.
	 */
	private function render_php_file( $_view_file_path_, $params = array() ) {
		ob_start();
		ob_implicit_flush( false );
		$reserved_names = array(
			'_view_file_path_',
			'params',
			'param_name',
			'param_value',
			'reserved_names',
			'GLOBALS',
			'this',
		);
		foreach ( $params as $param_name => $param_value ) {
			if (
				is_string( $param_name )
				&& preg_match( '/^[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*$/', $param_name )
				&& ! in_array( $param_name, $reserved_names, true )
			) {
				${$param_name} = $param_value;
			}
		}
		unset( $param_name, $param_value, $reserved_names );
		require $_view_file_path_;

		return ob_get_clean();
	}
}
