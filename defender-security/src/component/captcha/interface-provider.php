<?php
/**
 * Captcha provider interface.
 *
 * @package WP_Defender\Component\Captcha
 */

namespace WP_Defender\Component\Captcha;

use WP_Defender\Integrations\Buddypress;
use WP_Defender\Integrations\Woocommerce;

/**
 * Interface for captcha providers.
 *
 * Defines the contract for all captcha provider implementations.
 */
interface Interface_Provider {
	/**
	 * Get the captcha response token from the current request.
	 *
	 * @return string The response token or empty string if not found.
	 */
	public function get_response(): string;

	/**
	 * Get API script URL.
	 *
	 * @return string
	 */
	public function get_api_url(): string;

	/**
	 * Get verification URL.
	 *
	 * @return string
	 */
	public function get_verify_url(): string;

	/**
	 * Get script handle name.
	 *
	 * @return string
	 */
	public function get_script_handle(): string;

	/**
	 * Get frontend script URL.
	 *
	 * @return string
	 */
	public function get_script_url(): string;

	/**
	 * Get provider name.
	 *
	 * @param bool $is_type Get provider name by type.
	 *
	 * @return string
	 */
	public function get_name( bool $is_type = false ): string;

	/**
	 * Get widget options.
	 *
	 * @return array
	 */
	public function get_options(): array;

	/**
	 * Render the provider widget HTML.
	 *
	 * @return string
	 */
	public function render_widget(): string;

	/**
	 * Get API script configuration.
	 *
	 * @return array
	 */
	public function get_api_script(): array;

	/**
	 * Get list of excluded requests.
	 *
	 * @return array
	 */
	public function get_excluded_requests(): array;

	/**
	 * Get list of duplicate script handles.
	 *
	 * @return array
	 */
	public function get_duplicate_script_handles(): array;

	/**
	 * Get regex pattern for duplicate scripts.
	 *
	 * @return string
	 */
	public function get_duplicate_script_pattern(): string;

	/**
	 * Verify a captcha response token via remote request.
	 *
	 * @param string $token Response token.
	 * @param string $url   Endpoint URL.
	 * @param array  $body  Additional request body data.
	 *
	 * @return array
	 */
	public function verify_response_token( string $token, string $url, array $body = array() ): array;

	/**
	 * Get formatted error message for display.
	 *
	 * @return string
	 */
	public function error_message(): string;

	/**
	 * Determine whether to skip checks for this form.
	 *
	 * @param Woocommerce $woo WooCommerce integration.
	 * @param Buddypress  $buddypress BuddyPress integration.
	 *
	 * @return bool
	 */
	public function should_skip_check( Woocommerce $woo, Buddypress $buddypress ): bool;

	/**
	 * Verify response for a specific form.
	 *
	 * @param string $form Form identifier.
	 *
	 * @return bool
	 */
	public function verify_response( string $form ): bool;

	/**
	 * Build admin notice data for the captcha settings UI.
	 *
	 * @param bool $is_woo_activated Whether WooCommerce is active.
	 * @param bool $is_buddypress_activated Whether BuddyPress is active.
	 *
	 * @return array
	 */
	public function get_notice_data( bool $is_woo_activated, bool $is_buddypress_activated ): array;
}
