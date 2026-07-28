<?php
/**
 * Manages the protection against information disclosure by configuring server settings.
 *
 * @package WP_Defender\Component\Security_Tweaks
 */

namespace WP_Defender\Component\Security_Tweaks;

use WP_Error;
use WP_Defender\Component\Security_Tweaks\Servers\Server;

/**
 * Class Protect_Information
 */
class Protect_Information extends Abstract_Security_Tweaks {

	/**
	 * Slug identifier for the component.
	 *
	 * @var string
	 */
	public string $slug = 'protect-information';

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
	 * @param  string $current_server  The current server software being used.
	 *
	 * @return bool|WP_Error
	 */
	public function process( $current_server ) {
		if ( 'apache' === $current_server || 'litespeed' === $current_server ) {
			// Because the Prevent_PHP tweak uses the 'process' method too.
			return Server::create( $current_server )->from( $this->slug )->process( false );
		} else {

			return Server::create( $current_server )->from( $this->slug )->process();
		}
	}

	/**
	 * This is for un-do stuff that has been done in @process.
	 *
	 * @param  string|null $current_server  The current server software being used.
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
		return wp_strip_all_tags( __( 'Prevent info disclosure', 'defender-security' ) );
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
			'errorReason'      => $this->get_error_reason(),
			'successReason'    => wp_strip_all_tags( __( 'Sensitive files are locked.', 'defender-security' ) ),
			'misc'             => array(
				'active_server'      => Server::get_current_server(),
				'apache_rules'       => Server::create( 'apache' )->from( $this->slug )->get_rules_for_instruction(),
				'litespeed_rules'    => Server::create( 'litespeed' )->from( $this->slug )->get_rules_for_instruction(),
				'nginx_rules'        => Server::create( 'nginx' )->from( $this->slug )->get_rules(),
				'show_action_button' => true,
			),
			'bulk_description' => wp_strip_all_tags(
				__( 'Misconfigured servers can expose sensitive files, including config files, .htaccess files, and backups. Prevent info disclosure to protect private site details and reduce the risk of unauthorized access.', 'defender-security' )
			),
			'bulk_title'       => wp_strip_all_tags( __( 'Information Disclosure', 'defender-security' ) ),
		);
	}
}
