<?php

namespace WP_Defender;

use WP_Defender\Traits\Defender_Bootstrap;
use WP_Defender\Component\Rate;

/**
 * Class Bootstrap
 *
 * @package WP_Defender
 */
class Bootstrap {
	use Defender_Bootstrap;

	/**
	 * Activation.
	 */
	public function activation_hook(): void {
		$this->activation_hook_common();
		$this->set_free_installation_timestamp();
	}

	/**
	 * Add option with plugin install date.
	 *
	 * @since 2.4
	 */
	protected function set_free_installation_timestamp(): void {
		// Let's equate the plugin installation and postponed notice dates. This will simplify future checks.
		$install_date = (int) get_site_option( Rate::SLUG_FREE_INSTALL_DATE, 0 );
		if ( 0 === $install_date ) {
			update_site_option( Rate::SLUG_FREE_INSTALL_DATE, time() );
			update_site_option( Rate::SLUG_POSTPONED_NOTICE_DATE, time() );
		} else {
			update_site_option( Rate::SLUG_POSTPONED_NOTICE_DATE, $install_date );
		}
	}

	/**
	 * Load all modules.
	 */
	public function init_modules(): void {
		$this->init_modules_common();
	}

	/**
	 * Deactivation clears only free version cron hooks.
	 */
	public function deactivation_hook(): void {
		$this->deactivation_hook_common();
	}
}
