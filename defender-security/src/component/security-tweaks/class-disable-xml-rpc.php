<?php
/**
 * Responsible for disabling XML-RPC functionality in WordPress.
 *
 * @package WP_Defender\Component\Security_Tweaks
 */

namespace WP_Defender\Component\Security_Tweaks;

use WP_Defender\Traits\IO;
use WP_Defender\Behavior\WPMUDEV;

/**
 * XML-RPC can be a security risk if not properly managed, and this class provides methods to disable it and ensure it
 *  remains disabled.
 */
class Disable_XML_RPC extends Abstract_Security_Tweaks {

	use IO;

	/**
	 * Unique identifier for the tweak.
	 *
	 * @var string $slug
	 */
	public string $slug = 'disable-xml-rpc';

	/**
	 * Indicates whether the issue has been resolved.
	 *
	 * @var bool
	 */
	public bool $resolved = false;

	/**
	 * This class contains everything relate to WPMUDEV.
	 *
	 * @var WPMUDEV
	 */
	private WPMUDEV $wpmudev;

	/**
	 * Class constructor to initialize the Disable_XML_RPC component.
	 *
	 * @return void
	 */
	public function __construct() {
		$this->wpmudev = wd_di()->get( WPMUDEV::class );
	}

	/**
	 * This function processes the request to disable XML-RPC.
	 *
	 * @return bool Returns true if the function successfully executes.
	 */
	public function process(): bool {
		// Update the site option for the current instance of the class to "ON".
		update_site_option( $this->slug, 'ON' );

		// Return true to indicate that the function executed successfully.
		return true;
	}

	/**
	 * Reverts the XML-RPC toggle to the "off" state.
	 *
	 * @return bool Returns true if the function successfully executes.
	 */
	public function revert(): bool {
		// Set the XML-RPC toggle to "OFF".
		update_site_option( $this->slug, 'OFF' );

		// Return true to indicate that the function executed successfully.
		return true;
	}

	/**
	 * Shield up. It runs on every page load when xml-rpc is disabled.
	 *
	 * @return void
	 */
	public function shield_up(): void {
		// Check if this tweak has been enabled.
		$this->resolved = $this->check();
		// if this tweak is ON, block XML-RPC.
		if ( $this->resolved ) {
			$this->add_hooks();
		}
	}

	/**
	 * Queue hooks when this class init.
	 *
	 * @return void
	 */
	public function add_hooks(): void {
		// Disable XML-RPC methods that require authentication.
		add_filter( 'xmlrpc_enabled', '__return_false' );
		// Class used for handling XML-RPC requests.
		add_filter( 'wp_xmlrpc_server_class', array( $this, 'handle_send_forbidden_response' ) );
		// Methods exposed by the XML-RPC server.
		add_filter( 'xmlrpc_methods', '__return_empty_array' );
	}

	/**
	 * Check whether the issue has been resolved or not.
	 *
	 * @return bool
	 */
	public function check(): bool {
		return $this->is_tweak_enabled_in_site();
	}

	/**
	 * Re-check the XML-RPC status.
	 *
	 * @return bool
	 */
	public function recheck(): bool {
		// Check if XML-RPC is disabled on Defender (plugin) side.
		$plugin_xmlrpc_status = $this->is_tweak_enabled_in_site();
		// Check if user is using WPMUDEV hosting.
		if ( $this->wpmudev->is_wpmu_hosting() ) {
			$hosting_xmlrpc_status = $this->is_tweak_enabled_in_server();

			if ( $plugin_xmlrpc_status && $hosting_xmlrpc_status ) {
				return $this->revert();
			} else {
				return $plugin_xmlrpc_status || $hosting_xmlrpc_status;
			}
		}

		// Return the status of XML-RPC.
		return $plugin_xmlrpc_status;
	}

	/**
	 * Check whether the tweak is enabled or not in the site.
	 *
	 * @return bool
	 */
	public function is_tweak_enabled_in_site(): bool {
		return get_site_option( $this->slug ) === 'ON';
	}

	/**
	 * Check whether the tweak is enabled or not in the server.
	 *
	 * @return bool
	 */
	public function is_tweak_enabled_in_server(): bool {
		// Check if the current site is hosted by WPMU DEV.
		if ( ! $this->wpmudev->is_wpmu_hosting() ) {
			// If not, return true to indicate that the tweak is enabled by default.
			return true;
		}

		$server_xmlrpc_status = defender_get_hosting_feature_state( 'xmlrpc_block' );
		if ( '' === $server_xmlrpc_status ) {
			// Something went wrong.
			return false;
		}

		// Return whether the XML-RPC is enabled or disabled based on the XML-RPC status.
		return ! $server_xmlrpc_status;
	}

	/**
	 * Send a 403 Forbidden response and terminate the script.
	 *
	 * @return void
	 */
	public function send_forbidden_response(): void {
		http_response_code( 403 );
		exit( esc_html__( 'Forbidden', 'defender-security' ) );
	}

	/**
	 * Wraps the send_forbidden_response method to fix PHPStan error.
	 *
	 * @param string $callback_class Class name passed by the filter.
	 */
	public function handle_send_forbidden_response( string $callback_class ): string {
		$this->send_forbidden_response();

		// Unreachable, but required for PHPStan. Return the class name to satisfy the filter's expected return type.
		return $callback_class;
	}

	/**
	 * Retrieve the tweak's label.
	 *
	 * @return string
	 */
	public function get_label(): string {
		return esc_html__( 'Turn off XML-RPC', 'defender-security' );
	}

	/**
	 * Get the error reason.
	 *
	 * @return string
	 */
	public function get_error_reason(): string {
		return esc_html__( 'XML-RPC is currently enabled.', 'defender-security' );
	}

	/**
	 * Return a summary data of this tweak.
	 *
	 * @return array
	 */
	public function to_array(): array {
		// The message to display if the XML-RPC feature is disabled.
		$enabled = wp_strip_all_tags( __( 'XML-RPC is turned off.', 'defender-security' ) );
		// Determine if the XML-RPC feature is enabled on the server side.
		$in_server = $this->is_tweak_enabled_in_server();
		// Determine if the XML-RPC feature is enabled on the plugin side.
		$in_site = $this->is_tweak_enabled_in_site();

		// If the site is not hosted on WPMU DEV's hosting, return the summary data.
		if ( $this->wpmudev->is_wpmu_hosting() && $this->wpmudev->is_dash_activated() && $this->wpmudev->get_site_id() ) {
			// If the site is hosted on WPMU DEV's hosting, construct the URL to the hosting settings page.
			$url           = 'https://wpmudev.com/hub2/site/' . $this->wpmudev->get_site_id() . '/hosting/tools#block-xml-rpc';
			$is_whitelabel = $this->wpmudev->is_whitelabel_enabled();

			if ( $in_site && $in_server ) {
				$this->revert();
			}

			[ $enabled, $hosting_settings_url ] = match ( true ) {
				$in_server && $is_whitelabel => array(
					wp_strip_all_tags(
						__(
							'You can manage the XML-RPC settings in the Hosting Settings.',
							'defender-security'
						)
					),
					null,
				),
				$in_server => array( '', $url ),
				$is_whitelabel => array(
					wp_strip_all_tags(
						__(
							'XML-RPC is currently disabled on plugin side.',
							'defender-security'
						)
					),
					null,
				),
				default => array(
					wp_strip_all_tags(
						__(
							'XML-RPC is currently disabled on plugin side, we suggest disabling it from server side by clicking on this link.',
							'defender-security'
						)
					),
					$url,
				),
			};

			// Return the summary data.
			return array(
				'slug'             => $this->slug,
				'title'            => $this->get_label(),
				'errorReason'      => $this->get_error_reason(),
				'successReason'    => $enabled,
				'misc'             => array(
					'show_revert_button'   => ! $in_server,
					'hosting_settings_url' => $hosting_settings_url,
					'show_action_button'   => true,
				),
				'bulk_description' => wp_strip_all_tags( __( 'XML-RPC lets you publish to your WordPress site remotely using apps like the mobile app or services like IFTTT. If you don’t use remote publishing, turn off XML-RPC to help reduce security risk.', 'defender-security' ) ),
				'bulk_title'       => 'XML-RPC',
			);
		}

		return array(
			'slug'             => $this->slug,
			'title'            => $this->get_label(),
			'errorReason'      => $this->get_error_reason(),
			'successReason'    => $enabled,
			'misc'             => array(
				'show_revert_button' => $in_site,
				'show_action_button' => true,
			),
			'bulk_description' => wp_strip_all_tags( __( 'XML-RPC lets you publish to your WordPress site remotely using apps like the mobile app or services like IFTTT. If you don’t use remote publishing, turn off XML-RPC to help reduce security risk.', 'defender-security' ) ),
			'bulk_title'       => 'XML-RPC',
		);
	}
}
