<?php
/**
 * Handles fake bot detection functionality.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Controller;
use WP_Defender\Component\Blacklist_Lockout;
use WP_Defender\Component\Fake_Bot_Detection as Fake_Bot_Detection_Component;
use WP_Defender\Traits\IP;

/**
 * Handles operations to detect whether the current HTTP request comes from a legitimate bot.
 *
 * @package MyPlugin\Controllers
 */
class Fake_Bot_Detection extends Controller {
	use IP;

	/**
	 * Service for handling logic.
	 *
	 * @var Fake_Bot_Detection_Component
	 */
	protected $service;

	/**
	 * Constructor for the Fake_Bot_Detection class.
	 * Initializes the service and sets up necessary hooks.
	 *
	 * @param Fake_Bot_Detection_Component $service The service instance for fake bot functionality.
	 */
	public function __construct( Fake_Bot_Detection_Component $service ) {
		$this->service = $service;

		$service = wd_di()->get( Blacklist_Lockout::class );
		$ip      = $this->get_user_ip();

		if ( $this->service->is_enabled() && ! $service->are_ips_whitelisted( $ip ) ) {
			add_action( 'init', array( $this->service, 'load_crawlers' ) );
			add_action( 'init', array( $this->service, 'validate_legit_crawler' ) );
		}
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
		delete_site_transient( Fake_Bot_Detection_Component::CACHE_KEY );
		$this->service->clear_fb_transients();
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
	 *
	 * @throws Exception If table is not defined.
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
