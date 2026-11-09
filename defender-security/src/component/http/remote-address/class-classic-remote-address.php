<?php
/**
 * Handles retrieval of client IP addresses from HTTP headers.
 *
 * @package    WP_Defender\Component\Http\Remote_Address
 */

namespace WP_Defender\Component\Http\Remote_Address;

use WP_Defender\Traits\IP;

/**
 * Older way of getting the client/Remote IP address on HTTP request.
 */
class Classic_Remote_Address {

	use IP;

	/**
	 * List of HTTP headers that may contain the client IP address.
	 *
	 * @var array
	 */
	private $accepted_header = array(
		'HTTP_CLIENT_IP',
		'HTTP_X_REAL_IP',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_X_CLUSTER_CLIENT_IP',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED',
		'HTTP_CF_CONNECTING_IP',
		'REMOTE_ADDR',
	);

	/**
	 * Whether the immediate peer (REMOTE_ADDR) is a configured trusted proxy.
	 *
	 * Mirrors the trust gate in Remote_Address::get_ip_address_from_proxy(). With no trusted
	 * proxies configured nothing is trusted, so only REMOTE_ADDR is used and a spoofed
	 * forwarded header can no longer attribute a request to another IP.
	 *
	 * @param  array $server  The raw $_SERVER data.
	 *
	 * @return bool
	 * @since 5.7.1
	 */
	protected function is_peer_trusted_proxy( array $server ): bool {
		$remote_address = isset( $server['REMOTE_ADDR'] ) ? trim( (string) $server['REMOTE_ADDR'] ) : '';
		if ( false === filter_var( $remote_address, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$trusted_proxies = wd_di()->get( \WP_Defender\Model\Setting\Firewall::class )->get_trusted_proxies_ip();
		$trusted_proxies = apply_filters( 'wpdef_firewall_trusted_proxies', $trusted_proxies );
		$trusted_proxies = is_array( $trusted_proxies ) ? $trusted_proxies : (array) $trusted_proxies;

		foreach ( $trusted_proxies as $trusted_proxy ) {
			$trusted_proxy = trim( (string) $trusted_proxy );
			if ( '' === $trusted_proxy ) {
				continue;
			}
			if (
				( str_contains( $trusted_proxy, '/' ) && $this->compare_cidr( $remote_address, $trusted_proxy ) ) ||
				$trusted_proxy === $remote_address
			) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns client IP addresses.
	 *
	 * @return array IP addresses
	 */
	public function get_ip_address(): array {
		$ip_list = array();
		$server  = defender_get_data_from_request( null, 's' );
		$trusted = $this->is_peer_trusted_proxy( $server );
		foreach ( $this->accepted_header as $key ) {
			// Forwarded headers are attacker-controlled unless the immediate peer is a trusted proxy.
			if ( 'REMOTE_ADDR' !== $key && ! $trusted ) {
				continue;
			}
			if ( array_key_exists( $key, $server ) && is_string( $server[ $key ] ) && '' !== $server[ $key ] ) {
				$ip_array = explode( ',', $server[ $key ] );
				foreach ( $ip_array as $ip ) {
					$ip = trim( $ip );
					if ( $this->check_validate_ip( $ip ) ) {
						$ip_list[] = $ip;
					}
				}
			}
		}

		return $ip_list;
	}

	/**
	 * Return all the headers found.
	 *
	 * @return array Header(s) key/name.
	 */
	public function get_ip_header(): array {
		$header_array = array();
		$server       = defender_get_data_from_request( null, 's' );
		$trusted      = $this->is_peer_trusted_proxy( $server );
		foreach ( $this->accepted_header as $key ) {
			// Keep in step with get_ip_address(): skip untrusted forwarded headers.
			if ( 'REMOTE_ADDR' !== $key && ! $trusted ) {
				continue;
			}
			if ( array_key_exists( $key, $server ) && is_string( $server[ $key ] ) && '' !== $server[ $key ] ) {
				$ip_array = explode( ',', $server[ $key ] );
				foreach ( $ip_array as $ip ) {
					$ip = trim( $ip );
					if ( $this->check_validate_ip( $ip ) ) {
						$header_array[] = $key;
						break;
					}
				}
			}
		}

		return $header_array;
	}
}
