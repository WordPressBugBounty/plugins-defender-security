<?php
/**
 * Handles the functionality for detecting the IP header to be used on the site.
 *
 * @package    WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Error;
use WP_Defender\Component;
use WP_Defender\Controller\Firewall;
use WP_Defender\Model\Setting\Firewall as Model_Firewall;
use WP_Defender\Component\Http\Remote_Address\Remote_Address;
use WP_Defender\Component\Trusted_Proxy_Preset\Cloudflare_Proxy;

/**
 * Handles the functionality for detecting the IP header to be used on the site.
 *
 * @since 4.9.0
 */
class Smart_Ip_Detection extends Component {
	/**
	 * The version of the API.
	 *
	 * @var string
	 */
	public const API_VERSION = '1';

	/**
	 * The namespace of the API.
	 *
	 * @var string
	 */
	public const API_NAMESPACE = 'wpdef';

	/**
	 * The route of the API.
	 *
	 * @var string
	 */
	public const API_ROUTE = 'detect-ip-header';

	/**
	 * The IP header detected by Smart IP Detection.
	 *
	 * @var string
	 */
	public const SMART_IP_DETECTION_HEADER = 'wd_smart_ip_detection_header';

	/**
	 * The list of IP services.
	 *
	 * @var array
	 */
	public const IP_SERVICES = array(
		'https://api.ipify.org',
		'https://checkip.amazonaws.com',
		'https://ipinfo.io/ip',
	);

	/**
	 * AJAX action for the ping.
	 *
	 * @var string
	 */
	public const ACTION_PING = 'defender_smart_ip_detection_ping';

	/**
	 * Get namespace with version.
	 *
	 * @return string
	 */
	public static function get_namespace(): string {
		return self::API_NAMESPACE . '/v' . self::API_VERSION;
	}

	/**
	 * Get the route of the API.
	 *
	 * @return string
	 */
	public static function get_route(): string {
		return '/' . self::API_ROUTE;
	}

	/**
	 * Check if the IP detection is set to automatic.
	 *
	 * @return bool True if the IP detection is set to automatic, false otherwise.
	 */
	public function is_smart_ip_detection_enabled(): bool {
		$model = wd_di()->get( Model_Firewall::class );
		return 'automatic' === $model->ip_detection_type;
	}

	/**
	 * Detect the IP header based on the known IP(s).
	 *
	 * @return array|WP_Error The detected IP & header, or an error message if the header is not found.
	 */
	public function smart_ip_detect_header() {
		$headers_to_check = array(
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
			'HTTP_X_FORWARDED_FOR',
		);

		$known_ips = array(
			$this->get_server_public_ip(),
			'127.0.0.1',
		);

		$server_addr = defender_get_data_from_request( 'SERVER_ADDR', 's' );
		if ( $this->validate_ip( $server_addr ) ) {
			$known_ips[] = $server_addr;
		}
		$known_ips = array_unique( $known_ips );

		foreach ( $headers_to_check as $header ) {
			$ips = defender_get_data_from_request( $header, 's' );
			if ( ! is_null( $ips ) && '' !== $ips ) {
				$ips = array_map( 'trim', preg_split( '/[\s,]+/', $ips ) );
				foreach ( $ips as $ip ) {
					if ( in_array( $ip, $known_ips, true ) ) {
						update_site_option( self::SMART_IP_DETECTION_HEADER, $header );

						$msg = sprintf(
						/* translators: 1. IP header. 2. IP. */
							esc_html__( 'IP header detected: %1$s with IP: %2$s.', 'defender-security' ),
							$header,
							$ip
						);
						$this->log( 'Smart IP DETECTION: ' . $msg, Firewall::FIREWALL_LOG );
						return array(
							'header'  => $header,
							'ip'      => $ip,
							'message' => $msg,
						);
					}
				}
			}
		}

		$msg = sprintf(
			/* translators: 1. IP(s) */
			esc_html__( 'Not able to find any IP header via IP(s): %s.', 'defender-security' ),
			implode( ',', $known_ips )
		);
		$this->log( 'Smart IP DETECTION: ' . $msg, Firewall::FIREWALL_LOG );
		return new WP_Error(
			'defender_smart_ip_detection_no_header',
			$msg
		);
	}

	/**
	 * Send request to the API endpoint for IP detection.
	 *
	 * @param bool $is_skipped Whether to skip the check if Smart IP Detection is enabled.
	 *
	 * @return bool True if the request is sent successfully, false otherwise.
	 */
	public function smart_ip_detection_ping( bool $is_skipped = false ): bool {
		if ( ! $is_skipped && ! $this->is_smart_ip_detection_enabled() ) {
			$this->log( 'Smart IP DETECTION: IP Detection is not set to \'automatic\'', Firewall::FIREWALL_LOG );
			return false;
		}

		$nonce = bin2hex( Crypt::random_bytes( 32 ) );
		set_transient( self::get_nonce_context(), $nonce, MINUTE_IN_SECONDS );

		$url      = add_query_arg(
			array(
				'action' => self::ACTION_PING,
				'nonce'  => $nonce,
			),
			admin_url( 'admin-ajax.php' )
		);
		$args     = array(
			'sslverify' => true,
		);
		$response = wp_remote_get( $url, $args );

		if ( is_wp_error( $response ) ) {
			$this->log( 'Smart IP DETECTION: ' . $response->get_error_message(), Firewall::FIREWALL_LOG );
			return false;
		} elseif ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			$this->log( 'Smart IP DETECTION: ' . wp_remote_retrieve_response_message( $response ), Firewall::FIREWALL_LOG );
			return false;
		} else {
			$this->log( 'Smart IP DETECTION: Pinged successfully.', Firewall::FIREWALL_LOG );
			return true;
		}
	}

	/**
	 * Get the details of the Smart IP Detection.
	 *
	 * Context: the saved header is written by smart_ip_detect_header() (this class) during the detection ping; it may
	 * be any header the ping matched, including REMOTE_ADDR. only headers in
	 * Component\Firewall::custom_http_headers() (src/component/class-firewall.php) are read, through
	 * Remote_Address::get_ip_address() (src/component/http/remote-address/class-remote-address.php), which uses the
	 * header only when REMOTE_ADDR is a trusted proxy (manual list after the wpdef_firewall_trusted_proxies filter, or
	 * preset) and walks it right to left. with no preset set, CF-Connecting-IP trusts Cloudflare's ranges;
	 * Cloudflare_Proxy::get_ips() (src/component/trusted-proxy-preset/class-cloudflare-proxy.php) reads them from the
	 * wpdef_cloudflare_ips site option and fetches them over HTTP when the option is missing. callers are
	 * get_user_ip() and get_user_ip_header() (src/traits/ip.php) and Controller\Firewall::sync_ip_header();
	 * get_user_ip() feeds Login Lockout, bans, the allowlist and logs, so this returns exactly one IP. with
	 * no REMOTE_ADDR (CLI, cron) it returns 127.0.0.1.
	 *
	 * @return array The details of the IP and header.
	 */
	public function get_smart_ip_detection_details(): array {
		$header = (string) get_site_option( self::SMART_IP_DETECTION_HEADER, '' );
		$model  = wd_di()->get( Model_Firewall::class );
		$preset = $model->get_trusted_proxy_preset();
		// Cloudflare sites rarely configure trusted proxies, so trust its published ranges for its own header.
		if ( '' === $preset && 'HTTP_CF_CONNECTING_IP' === $header ) {
			$preset = Cloudflare_Proxy::PROXY_SLUG;
		}

		// The saved header is honoured only when REMOTE_ADDR is a trusted proxy, as in manual mode.
		$use_proxy = in_array( $header, Component\Firewall::custom_http_headers(), true );
		$resolver  = ( new Remote_Address() )
			->set_use_proxy( $use_proxy )
			->set_trusted_proxies( $model->get_trusted_proxies_ip() )
			->set_trusted_proxy_preset( $preset );
		if ( $use_proxy ) {
			$resolver->set_proxy_header( $header );
		}

		$ip = $resolver->get_ip_address();
		if ( '' === $ip ) {
			return array( '127.0.0.1', 'REMOTE_ADDR' );
		}

		return array( $ip, defender_get_data_from_request( 'REMOTE_ADDR', 's' ) === $ip ? 'REMOTE_ADDR' : $header );
	}

	/**
	 * Remove the IP header detected by Smart IP Detection.
	 */
	public static function remove_header(): void {
		delete_site_option( self::SMART_IP_DETECTION_HEADER );
	}

	/**
	 * Get server's public IP from various sources.
	 *
	 * @return string
	 */
	public function get_server_public_ip(): string {
		$ip = '';

		foreach ( self::IP_SERVICES as $service ) {
			$response = wp_remote_get( $service );
			if ( ! is_wp_error( $response ) ) {
				$ip = trim( wp_remote_retrieve_body( $response ) );
				if ( $this->validate_ip( $ip ) ) {
					return $ip;
				}
			}
		}

		return $ip;
	}

	/**
	 * Get the nonce context for the AJAX action.
	 */
	public static function get_nonce_context(): string {
		return self::ACTION_PING . '_ajax_nonce';
	}
}
