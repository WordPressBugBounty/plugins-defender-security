<?php
/**
 * Cross_Sell class.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use Calotes\Base\Component;
use WP_Defender\Behavior\WPMUDEV;

/**
 * Handles the functionality related to the Cross-Sell module.
 *
 * @since 5.2.1
 */
class Cross_Sell extends Component {

	/**
	 * Checks if the Cross-Sell should render its UI.
	 *
	 * Should load only for a free version and non-hosted sites.
	 *
	 * @return bool
	 */
	protected function should_render(): bool {
		return defender_is_wp_org_version() && ! wd_di()->get( WPMUDEV::class )->is_wpmu_hosting();
	}

	/**
	 * Initialize the Cross-Sell module and set its options.
	 *
	 * @return void
	 */
	public function init() {
		$cross_sell_path = defender_path( 'extra/plugins-cross-sell-page/plugin-cross-sell.php' );
		if ( ! $this->should_render() || ! file_exists( $cross_sell_path ) ) {
			return;
		}

		static $cross_sell = null;
		if ( is_null( $cross_sell ) ) {
			if ( ! class_exists( '\WPMUDEV\Modules\Plugin_Cross_Sell' ) ) {
				require_once $cross_sell_path;
			}

			$submenu_params = array(
				'slug'            => 'defender-security', // Required.
				'parent_slug'     => 'wp-defender', // Required.
				'menu_slug'       => 'defender_cross_sell', // Optional - Strongly recommended to set in order to avoid admin page conflicts with other WPMU DEV plugins.
				'position'        => 17, // Optional – Usually a specific position will be required.
				'translation_dir' => defender_path( 'languages' ), // Optional – The directory where the translation files are located.
			);
			$cross_sell     = new \WPMUDEV\Modules\Plugin_Cross_Sell( $submenu_params );
		}
	}
}
