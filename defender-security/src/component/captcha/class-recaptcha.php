<?php
/**
 * ReCAPTCHA provider implementation.
 *
 * @package WP_Defender\Component\Captcha
 */

namespace WP_Defender\Component\Captcha;

use WP_Defender\Integrations\Buddypress;
use WP_Defender\Integrations\Woocommerce;

/**
 * Google reCAPTCHA provider.
 */
class Recaptcha extends Provider {

	/**
	 * Get the request field name for responses.
	 *
	 * @return string
	 */
	protected function get_response_field(): string {
		return 'g-recaptcha-response';
	}

	/**
	 * Get script handle name.
	 *
	 * @return string
	 */
	public function get_script_handle(): string {
		return 'wpdef_recaptcha_script';
	}

	/**
	 * Get frontend script URL.
	 *
	 * @return string
	 */
	public function get_script_url(): string {
		return 'assets/js/recaptcha_frontend.js';
	}

	/**
	 * Get widget options.
	 *
	 * @return array
	 */
	public function get_options(): array {
		$options = array(
			'version' => $this->type,
			'sitekey' => $this->key,
			'hl'      => $this->language,
			'size'    => $this->size,
			'error'   => $this->get_duplicate_captcha_warning(),
			// For default comment form.
			'disable' => '',
		);
		if ( 'v2_checkbox' === $this->type ) {
			$options['theme'] = $this->theme;
		}

		return $options;
	}

	/**
	 * Get provider name.
	 *
	 * @param bool $is_type Get provider name by type.
	 *
	 * @return string
	 */
	public function get_name( bool $is_type = false ): string {
		if ( $is_type ) {
			return $this->model->labels()[ $this->type ];
		}
		return __( 'reCAPTCHA', 'defender-security' );
	}

	/**
	 * Get widget content HTML.
	 *
	 * @param int $id Unique widget id.
	 *
	 * @return string
	 */
	protected function get_widget_content( int $id ): string {
		$content = '';
		if ( in_array( $this->type, array( 'v2_checkbox', 'v2_invisible' ), true ) ) {
			$content .= sprintf(
				'<div id="wpdef_recaptcha_%s" class="wpdef_recaptcha"></div>',
				esc_attr( $id )
			);
			$content .= '<noscript>
				<div style="width: 302px;">
					<div style="width: 302px; height: 422px; position: relative;">
						<div style="width: 302px; height: 422px; position: absolute;">
							<iframe src="https://www.google.com/recaptcha/api/fallback?k=' . esc_attr( $this->key ) . '"
								frameborder="0" scrolling="no" style="width: 302px; height:422px; border-style: none;"></iframe>
						</div>
					</div>
					<div
						style="bottom: 12px; left: 25px; margin: 0; padding: 0; right: 25px; background: #f9f9f9; border: 1px solid #c1c1c1; border-radius: 3px; height: 60px; width: 300px;">
						<textarea name="g-recaptcha-response" class="g-recaptcha-response"
							style="width: 250px !important; height: 40px !important; border: 1px solid #c1c1c1 !important; margin: 10px 25px !important; padding: 0 !important; resize: none !important;"></textarea>
					</div>
				</div>
			</noscript>';
		} elseif ( 'v3_recaptcha' === $this->type ) {
			$content .= sprintf(
				'<div id="wpdef_recaptcha_%s" class="wpdef_recaptcha"><input type="hidden" class="g-recaptcha-response" name="g-recaptcha-response" /></div>',
				esc_attr( $id )
			);
		}

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
			'deps'    => 'v3_recaptcha' === $this->type ? array() : array( 'jquery' ),
			'version' => DEFENDER_VERSION,
		);
	}

	/**
	 * Get API script URL.
	 *
	 * @return string
	 */
	public function get_api_url(): string {
		if ( 'v3_recaptcha' === $this->type ) {
			return sprintf(
				'https://www.google.com/recaptcha/api.js?hl=%s&render=%s',
				$this->language,
				$this->key
			);
		}

		return sprintf(
			'https://www.google.com/recaptcha/api.js?hl=%s&render=explicit',
			$this->language
		);
	}

	/**
	 * Get verification URL.
	 *
	 * @return string
	 */
	public function get_verify_url(): string {
		return 'https://www.google.com/recaptcha/api/siteverify';
	}

	/**
	 * Get list of excluded requests.
	 *
	 * @return array
	 */
	public function get_excluded_requests(): array {
		$requests = $this->filter_excluded_requests();

		/**
		 * Filters request slugs to exclude from reCAPTCHA checks.
		 *
		 * @param array $requests Request slugs to exclude.
		 *
		 * @since 2.5.6
		 * @deprecated 5.9.0 Use wd_captcha_excluded_requests instead.
		 */
		$requests = apply_filters_deprecated(
			'wd_recaptcha_excluded_requests',
			array( $requests ),
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
				'forminator-google-recaptcha',
			)
		);

		/**
		 * Filters script handles to exclude from reCAPTCHA duplication checks.
		 *
		 * @param array $handles Script handles to ignore when checking for duplicates.
		 *
		 * @since 2.5.6
		 * @deprecated 5.9.0 Use wd_captcha_excluded_handles instead.
		 */
		$handles = apply_filters_deprecated(
			'wd_recaptcha_excluded_handles',
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
		return '|google\.com/recaptcha/api\.js|';
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
		/**
		 * Filters the remote IP address for reCAPTCHA verification.
		 *
		 * @param string $user_ip The remote IP address.
		 *
		 * @since 2.5.6
		 * @deprecated 5.9.0 Use wd_captcha_remote_ip instead.
		 */
		$user_ip          = apply_filters_deprecated(
			'wd_recaptcha_remote_ip',
			array( $this->get_primary_ip() ),
			'5.9.0',
			'wd_captcha_remote_ip',
			__( 'Use wd_captcha_remote_ip to filter remote IP for all captcha providers.', 'defender-security' )
		);
		$response_keys    = $this->verify_response_token(
			$this->get_response(),
			$this->get_verify_url(),
			array(
				'remoteip' => is_string( $user_ip ) ? $user_ip : (string) $user_ip,
			)
		);
		$response_success = (bool) ( $response_keys['success'] ?? false );
		if ( 'v3_recaptcha' === $this->type && $response_success ) {
			$score            = (float) ( $response_keys['score'] ?? 0.0 );
			$response_success = $score >= $this->threshold;
		}

		$response_success = $this->filter_check_result( $response_success, $form );

		/**
		 * Filters the result of a reCAPTCHA verification.
		 *
		 * @param bool   $response_success The result of the reCAPTCHA verification.
		 * @param string $form             The form being verified.
		 *
		 * @since 2.5.6
		 * @deprecated 5.9.0 Use wd_captcha_check_result instead.
		 */
		$result = apply_filters_deprecated(
			'wd_recaptcha_check_result',
			array( $response_success, $form ),
			'5.9.0',
			'wd_captcha_check_result',
			__( 'Use wd_captcha_check_result to filter captcha verification for all providers.', 'defender-security' )
		);
		return is_bool( $result ) ? $result : (bool) $result;
	}

	/**
	 * Get provider settings from model.
	 *
	 * @return array
	 */
	protected function get_data(): array {
		$type_data_map = array(
			'v3_recaptcha' => $this->model->data_v3_recaptcha ?? array(),
			'v2_checkbox'  => $this->model->data_v2_checkbox ?? array(),
			'v2_invisible' => $this->model->data_v2_invisible ?? array(),
		);

		$data = $type_data_map[ $this->type ] ?? array();

		$data = wp_parse_args(
			$data,
			array(
				'key'       => '',
				'secret'    => '',
				'style'     => '',
				'size'      => 'invisible',
				'message'   => '',
				'threshold' => 0.0,
			)
		);

		$defaults        = $this->model->get_default_values();
		$data['message'] = '' !== $this->model->message ? $this->model->message : $defaults['message'];

		return $data;
	}
}
