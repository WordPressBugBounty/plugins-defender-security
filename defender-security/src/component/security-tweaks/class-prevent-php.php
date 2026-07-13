<?php
/**
 * Prevents PHP execution in directories that should not execute PHP.
 *
 * @package WP_Defender\Component\Security_Tweaks
 */

namespace WP_Defender\Component\Security_Tweaks;

use WP_Error;
use WP_Defender\Component\Security_Tweaks\Servers\Server;

/**
 * Prevents PHP execution in directories that should not execute PHP.
 */
class Prevent_PHP extends Abstract_Security_Tweaks {

	/**
	 * Identifier for the security tweak.
	 *
	 * @var string
	 */
	public string $slug = 'prevent-php-executed';

	/**
	 * Check whether the issue has been resolved or not.
	 *
	 * @return bool
	 */
	public function check() {
		return Server::create( Server::get_current_server() )->from( $this->slug )->check();
	}

	/**
	 * Here is the code for processing, if the return is true, we add it to resolve list, WP_Error if any error.
	 *
	 * @param  string $current_server  The server on which to apply the configuration.
	 *
	 * @return bool|WP_Error
	 */
	public function process( $current_server ) {
		return Server::create( $current_server )->from( $this->slug )->process();
	}

	/**
	 * This is for un-do stuff that has be done in @process.
	 *
	 * @param  string|null $current_server  The server on which to apply the configuration.
	 *
	 * @return bool|WP_Error
	 */
	public function revert( $current_server = null ) {
		if ( is_null( $current_server ) ) {
			$current_server = Server::get_current_server();
		}

		return Server::create( $current_server )->from( $this->slug )->revert();
	}

	/**
	 * Shield up.
	 *
	 * @return bool
	 */
	public function shield_up() {
		return true;
	}

	/**
	 * Retrieve the tweak's label.
	 *
	 * @return string
	 */
	public function get_label(): string {
		return wp_strip_all_tags( __( 'Prevent PHP execution', 'defender-security' ) );
	}

	/**
	 * Get the error reason.
	 *
	 * @return string
	 */
	public function get_error_reason(): string {
		return '';
	}

	/**
	 * Return a summary data of this tweak.
	 *
	 * @return array
	 */
	public function to_array(): array {
		return array(
			'slug'             => $this->slug,
			'title'            => $this->get_label(),

			'successReason'    => wp_strip_all_tags( __( "You've disabled PHP execution, good stuff.", 'defender-security' ) ),
			'misc'             => array(
				'active_server'   => Server::get_current_server(),
				'apache_rules'    => Server::create( 'apache' )->from( $this->slug )->get_rules_for_instruction(),
				'litespeed_rules' => Server::create( 'litespeed' )->from( $this->slug )->get_litespeed_rules_for_instruction(),
				'nginx_rules'     => Server::create( 'nginx' )->from( $this->slug )->get_rules(),
				'wp_content_dir'  => WP_CONTENT_DIR,
			),
			'bulk_description' => wp_strip_all_tags( __( 'A plugin or theme vulnerability can allow harmful PHP files to run in your site directories. Prevent PHP execution where it isn’t needed to help block malicious files and reduce risk.', 'defender-security' ) ),
			'bulk_title'       => wp_strip_all_tags( __( 'PHP Execution', 'defender-security' ) ),
		);
	}
}
