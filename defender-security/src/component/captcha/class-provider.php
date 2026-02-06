<?php
/**
 * Base provider for captcha integrations.
 *
 * @package WP_Defender\Component\Captcha
 */

namespace WP_Defender\Component\Captcha;

use WP_Defender\Traits\IP;
use WP_Defender\Component\Crypt;
use WP_Defender\Model\Setting\Captcha;

/**
 * Abstract captcha provider.
 */
abstract class Provider implements Interface_Provider {

	use IP;

	/**
	 * Captcha settings model.
	 *
	 * @var Captcha
	 */
	protected Captcha $model;

	/**
	 * Score threshold for v3.
	 *
	 * @var float
	 */
	protected float $threshold = 0.1;

	/**
	 * Widget language.
	 *
	 * @var string
	 */
	protected string $language = 'auto';

	/**
	 * Widget size.
	 *
	 * @var string
	 */
	protected string $size = 'normal';

	/**
	 * Widget theme.
	 *
	 * @var string
	 */
	protected string $theme = '';

	/**
	 * Secret key.
	 *
	 * @var string
	 */
	protected string $secret = '';

	/**
	 * Site key.
	 *
	 * @var string
	 */
	protected string $key = '';

	/**
	 * Captcha type.
	 *
	 * @var string
	 */
	public string $type = '';

	/**
	 * Error message.
	 *
	 * @var string
	 */
	protected string $message = '';

	/**
	 * Provider constructor.
	 *
	 * @param Captcha $model Captcha settings model.
	 */
	public function __construct( Captcha $model ) {
		$this->model   = $model;
		$this->type    = $this->model->active_type;
		$data          = $this->get_data();
		$this->key     = $data['key'];
		$this->secret  = $data['secret'];
		$this->theme   = $data['style'];
		$this->size    = $data['size'];
		$this->message = $data['message'];
		if ( isset( $data['threshold'] ) ) {
			$this->threshold = (float) $data['threshold'];
		}
		$this->language = $this->model->language;
	}

	/**
	 * Get provider settings from model.
	 *
	 * @return array
	 */
	abstract protected function get_data(): array;

	/**
	 * Get the response token from request.
	 *
	 * @return string
	 */
	public function get_response(): string {
		return stripslashes( defender_get_data_from_request( $this->get_response_field(), 'p' ) );
	}

	/**
	 * Get the request field name for responses.
	 *
	 * @return string
	 */
	abstract protected function get_response_field(): string;

	/**
	 * Get verification URL.
	 *
	 * @return string
	 */
	abstract public function get_verify_url(): string;

	/**
	 * Get formatted error message for display.
	 *
	 * @return string
	 */
	public function error_message(): string {
		return sprintf(
			/* translators: 1: Opening strong tag, 2: Closing strong tag, 3: Error message */
			esc_html__( '%1$sError:%2$s %3$s', 'defender-security' ),
			'<strong>',
			'</strong>',
			esc_html( $this->message )
		);
	}

	/**
	 * Get duplicate captcha warning message.
	 *
	 * @return string
	 */
	public function get_duplicate_captcha_warning(): string {
		return sprintf(
			/* translators: 1: Opening strong tag, 2: Closing strong tag, 3: Captcha type name */
			esc_html__( '%1$sWarning:%2$s&nbsp; More than one %3$s has been found in the current form. Please remove all unnecessary %3$s fields to make it work properly.', 'defender-security' ),
			'<strong>',
			'</strong>',
			esc_html( $this->get_name() )
		);
	}

	/**
	 * Render the provider widget HTML.
	 *
	 * @return string HTML markup for the captcha widget.
	 */
	public function render_widget(): string {
		// Generate random id to prevent duplicate IDs when multiple widgets are rendered.
		$id      = Crypt::random_int( 0, mt_getrandmax() );
		$content = sprintf( '<div class="captcha_wrap wpdef_captcha_%s">', esc_attr( $this->type ) );

		if ( '' === $this->key || '' === $this->secret ) {
			$content .= '</div>';
			return $content;
		}

		$content .= $this->get_widget_content( $id );
		$content .= '</div>';

		return $content;
	}

	/**
	 * Get provider widget content.
	 *
	 * @param int $id Unique widget id.
	 *
	 * @return string
	 */
	abstract protected function get_widget_content( int $id ): string;

	/**
	 * Build admin notice data for the captcha settings UI.
	 *
	 * @param bool $is_woo_activated Whether WooCommerce is active.
	 * @param bool $is_buddypress_activated Whether BuddyPress is active.
	 *
	 * @return array
	 */
	public function get_notice_data( bool $is_woo_activated, bool $is_buddypress_activated ): array {
		$is_active   = $this->model->is_active();
		$notice_type = 'warning';
		$notice_text = false;

		if ( $is_active ) {
			$has_location = $this->model->enable_default_location()
				|| $this->model->check_woo_locations( $is_woo_activated )
				|| $this->model->check_buddypress_locations( $is_buddypress_activated );
			if ( $has_location ) {
				$notice_type = 'success';
				$notice_text = false;
			} elseif ( ! $is_woo_activated && ! $is_buddypress_activated && ! $this->model->enable_default_location() ) {
				$notice_type = 'warning';
				$notice_text = sprintf(
					/* translators: 1: Captcha Provider name, 2: Captcha Type */
					esc_html__( '%1$s is currently inactive for all forms. You can deploy %2$s for specific forms in the CAPTCHA Locations below.', 'defender-security' ),
					$this->get_name(),
					$this->get_name( true )
				);
			} elseif ( ! $this->model->enable_default_location() && ( ( $is_woo_activated && ! $this->model->enable_woo_location() ) || ( $is_buddypress_activated && ! $this->model->enable_buddypress_location() ) ) ) {
				$notice_type = 'warning';
				$notice_text = sprintf(
					/* translators: 1: Captcha Provider name, 2: Opening bold tag, 3: Closing bold tag */
					esc_html__( '%1$s is currently inactive for all forms. You can deploy %1$s for specific forms in the %2$sCAPTCHA Locations%3$s, %2$sWooCommerce%3$s or %2$sBuddyPress%3$s settings below.', 'defender-security' ),
					$this->get_name(),
					'<b>',
					'</b>'
				);
			}
		} else {
			// Inactive case.
			$notice_type = 'error';
			$notice_text = esc_html__( 'Configure a CAPTCHA provider to verify users and prevent automated bots. Both reCAPTCHA and Cloudflare Turnstile are supported.', 'defender-security' );
		}

		return array(
			'notice_type' => $notice_type,
			'notice_text' => $notice_text,
		);
	}

	/**
	 * Get primary user IP address.
	 *
	 * @return string
	 */
	protected function get_primary_ip(): string {
		$ips = $this->get_user_ip();

		/**
		 * Filters the remote IP address for captcha verification.
		 *
		 * @param string   $user_ip       The remote IP address.
		 * @param string   $provider_type Captcha provider type.
		 *
		 * @since 5.9.0
		 */
		$ip = apply_filters( 'wd_captcha_remote_ip', $ips[0], $this->type );
		return is_string( $ip ) ? $ip : (string) $ip;
	}

	/**
	 * Filter the captcha verification result.
	 *
	 * @param bool   $result Verification result.
	 * @param string $form   Form identifier.
	 *
	 * @return bool
	 */
	protected function filter_check_result( bool $result, string $form ): bool {
		/**
		 * Filters the result of a captcha verification.
		 *
		 * @param bool     $result        The verification result.
		 * @param string   $form          The form being verified.
		 * @param string   $provider_type Captcha provider type.
		 *
		 * @since 5.9.0
		 */
		$result = apply_filters( 'wd_captcha_check_result', $result, $form, $this->type );
		return is_bool( $result ) ? $result : (bool) $result;
	}

	/**
	 * Filter excluded requests for captcha checks.
	 *
	 * @param array $requests Default excluded requests.
	 *
	 * @return array
	 */
	protected function filter_excluded_requests( array $requests = array() ): array {
		/**
		 * Filters the list of excluded request slugs for captcha verification.
		 *
		 * @param array  $requests      Request slugs to exclude from captcha checks.
		 * @param string $provider_type Captcha provider type.
		 *
		 * @since 5.9.0
		 */
		$requests = apply_filters( 'wd_captcha_excluded_requests', $requests, $this->type );
		return is_array( $requests ) ? $requests : (array) $requests;
	}

	/**
	 * Filter excluded script handles for duplicate captcha detection.
	 *
	 * @param array $handles Default excluded handles.
	 *
	 * @return array
	 */
	protected function filter_excluded_handles( array $handles = array() ): array {
		/**
		 * Filters the list of excluded script handles for duplicate captcha detection.
		 *
		 * @param array  $handles       Script handles to ignore when checking for duplicates.
		 * @param string $provider_type Captcha provider type.
		 *
		 * @since 5.9.0
		 */
		$handles = apply_filters( 'wd_captcha_excluded_handles', $handles, $this->type );
		return is_array( $handles ) ? $handles : (array) $handles;
	}

	/**
	 * Verify a captcha response via remote request.
	 *
	 * @param string $url  Endpoint URL.
	 * @param array  $body Request body.
	 *
	 * @return array
	 */
	protected function verify_request( string $url, array $body ): array {
		$response = wp_remote_post(
			$url,
			array(
				'body'      => $body,
				'sslverify' => false,
			)
		);
		if ( is_wp_error( $response ) ) {
			return array( 'success' => false );
		}

		$body          = wp_remote_retrieve_body( $response );
		$response_body = json_decode( $body, true );

		if ( ! is_array( $response_body ) || array() === $response_body ) {
			return array( 'success' => false );
		}

		return $response_body;
	}

	/**
	 * Verify a captcha response token via remote request.
	 *
	 * @param string $token Response token.
	 * @param string $url   Endpoint URL.
	 * @param array  $body  Additional request body data.
	 *
	 * @return array
	 */
	public function verify_response_token( string $token, string $url, array $body = array() ): array {
		if ( '' === $token ) {
			return array( 'success' => false );
		}

		$body = wp_parse_args(
			$body,
			array(
				'secret'   => $this->secret,
				'response' => $token,
			)
		);

		$response_body = $this->verify_request( $url, $body );

		return is_array( $response_body ) ? $response_body : array( 'success' => false );
	}
}
