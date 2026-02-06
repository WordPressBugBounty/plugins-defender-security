<?php
/**
 * Turnstile provider implementation.
 *
 * @package WP_Defender\Component\Captcha
 */

namespace WP_Defender\Component\Captcha;

use WP_Defender\Integrations\Buddypress;
use WP_Defender\Integrations\Woocommerce;

/**
 * Cloudflare Turnstile provider.
 */
class Turnstile extends Provider {

	/**
	 * Get provider settings from model.
	 *
	 * @return array
	 */
	protected function get_data(): array {
		$defaults = $this->model->get_default_values();
		$data     = $this->model->data_turnstile ?? array();

		$data = wp_parse_args(
			$data,
			array(
				'key'     => '',
				'secret'  => '',
				'style'   => '',
				'size'    => 'normal',
				'message' => '',
			)
		);

		$data['message'] = '' !== $data['message'] ? $data['message'] : $defaults['turnstile_message'];

		return $data;
	}

	/**
	 * Get the request field name for responses.
	 *
	 * @return string
	 */
	protected function get_response_field(): string {
		return 'wpdef-turnstile-response';
	}

	/**
	 * Get script handle name.
	 *
	 * @return string
	 */
	public function get_script_handle(): string {
		return 'wpdef_turnstile_script';
	}

	/**
	 * Get frontend script URL.
	 *
	 * @return string
	 */
	public function get_script_url(): string {
		return 'assets/js/turnstile.js';
	}

	/**
	 * Get widget options.
	 *
	 * @return array
	 */
	public function get_options(): array {
		return array(
			'sitekey' => $this->key,
			'theme'   => $this->theme,
			'lang'    => $this->language,
			'size'    => $this->size,
			'error'   => $this->get_duplicate_captcha_warning(),
			// For default comment form.
			'disable' => '',
		);
	}

	/**
	 * Get provider name.
	 *
	 * @param bool $is_type Get provider name by type.
	 *
	 * @return string
	 */
	public function get_name( bool $is_type = false ): string {
		return __( 'Turnstile', 'defender-security' );
	}

	/**
	 * Get widget content HTML.
	 *
	 * @param int $id Unique widget id.
	 *
	 * @return string
	 */
	protected function get_widget_content( int $id ): string {
		$content  = sprintf(
			'<div id="wpdef_turnstile_%s" class="wpdef_recaptcha"></div>',
			esc_attr( $id )
		);
		$content .= '<noscript>';
		$content .= '<div style="padding: 10px; border: 1px solid #cccccc; background-color: #f9f9f9; margin-top: 10px;">';
		$content .= sprintf(
			'<p>%s</p>',
			esc_html__( 'Please enable JavaScript to complete the security verification.', 'defender-security' )
		);
		$content .= '</div>';
		$content .= '</noscript>';

		return $content;
	}

	/**
	 * Get API script configuration.
	 *
	 * @return array
	 */
	public function get_api_script(): array {
		return array(
			'url'     => $this->get_api_url(),
			'deps'    => array(),
			'version' => null,
		);
	}

	/**
	 * Get API script URL.
	 *
	 * @return string
	 */
	public function get_api_url(): string {
		return 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=wpdefTurnstileCallback';
	}

	/**
	 * Get verification URL.
	 *
	 * @return string
	 */
	public function get_verify_url(): string {
		return 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
	}

	/**
	 * Get list of excluded requests.
	 *
	 * @return array
	 */
	public function get_excluded_requests(): array {
		/**
		 * Filters request slugs to exclude from Turnstile checks.
		 *
		 * @param array $requests Request slugs to exclude.
		 *
		 * @since 4.7.0
		 * @deprecated 5.9.0 Use wd_captcha_excluded_requests instead.
		 */
		$requests = apply_filters_deprecated(
			'wd_cloudflare_turnstile_excluded_requests',
			array( $this->filter_excluded_requests() ),
			'5.9.0',
			'wd_captcha_excluded_requests',
			__( 'Use wd_captcha_excluded_requests to filter excluded requests for all captcha providers.', 'defender-security' )
		);

		return is_array( $requests ) ? $requests : (array) $requests;
	}

	/**
	 * Get list of duplicate script handles.
	 *
	 * @return array
	 */
	public function get_duplicate_script_handles(): array {
		$handles = $this->filter_excluded_handles(
			array(
				'wpdef_captcha_api',
				'forminator-turnstile',
			)
		);

		/**
		 * Filters script handles to exclude from Turnstile duplication checks.
		 *
		 * @param array $handles Script handles to ignore when checking for duplicates.
		 *
		 * @since 4.7.0
		 * @deprecated 5.9.0 Use wd_captcha_excluded_handles instead.
		 */
		$handles = apply_filters_deprecated(
			'wd_turnstile_excluded_handles',
			array( $handles ),
			'5.9.0',
			'wd_captcha_excluded_handles',
			__( 'Use wd_captcha_excluded_handles to filter excluded script handles for all captcha providers.', 'defender-security' )
		);

		return is_array( $handles ) ? $handles : (array) $handles;
	}

	/**
	 * Get regex pattern for duplicate scripts.
	 *
	 * @return string
	 */
	public function get_duplicate_script_pattern(): string {
		return '|challenges\.cloudflare\.com/turnstile/v0/api\.js|';
	}

	/**
	 * Determine whether to skip checks for this form.
	 *
	 * @param Woocommerce $woo WooCommerce integration.
	 * @param Buddypress  $buddypress BuddyPress integration.
	 *
	 * @return bool
	 */
	public function should_skip_check( Woocommerce $woo, Buddypress $buddypress ): bool {
		return false;
	}

	/**
	 * Verify response for a specific form.
	 *
	 * @param string $form Form identifier.
	 *
	 * @return bool
	 */
	public function verify_response( string $form ): bool {
		$response = $this->verify_response_token(
			$this->get_response(),
			$this->get_verify_url(),
			array(
				'remoteip' => $this->get_primary_ip(),
			)
		);

		return $this->filter_check_result( (bool) ( $response['success'] ?? false ), $form );
	}
}
