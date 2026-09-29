<?php
/**
 * Abstract bot class.
 *
 * @package WP_Defender\Component\Known_Bots\Bots
 */

namespace WP_Defender\Component\Known_Bots\Bots;

use WP_Defender\Component\User_Agent;
use WP_Defender\Traits\IP;

/**
 * Abstract class for Bots.
 */
abstract class Abstract_Bot implements Bots_Interface {
	use IP;

	/**
	 * Normalizes a user agent string.
	 *
	 * @param string $user_agent The user agent to clean.
	 *
	 * @return string
	 */
	protected function normalize_ua( string $user_agent = '' ): string {
		if ( '' === $user_agent ) {
			$user_agent = defender_get_data_from_request( 'HTTP_USER_AGENT', 's' );
			if ( '' === $user_agent ) {
				return '';
			}
			$user_agent = User_Agent::fast_cleaning( $user_agent );
		}

		if ( function_exists( 'mb_strtolower' ) ) {
			return mb_strtolower( $user_agent, 'UTF-8' );
		}

		return strtolower( $user_agent );
	}

	/**
	 * Validates and normalizes an IP address for DNS comparisons.
	 *
	 * @param mixed $ip The IP address to normalize.
	 *
	 * @return string|false
	 */
	protected function normalize_ip_address( $ip ) {
		if ( ! is_string( $ip ) ) {
			return false;
		}

		$ip = trim( $ip );
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$packed_ip = inet_pton( $ip );

		return false === $packed_ip ? false : inet_ntop( $packed_ip );
	}

	/**
	 * Verifies an IP address using reverse and forward DNS lookup.
	 *
	 * @param string $ip             The IP address to verify.
	 * @param string $domain_pattern Regex pattern to match hostnames.
	 *
	 * @return bool
	 */
	protected function verify_dns( string $ip, string $domain_pattern ): bool {
		$normalized_ip = $this->normalize_ip_address( $ip );
		if ( false === $normalized_ip ) {
			return false;
		}

		$hostname = gethostbyaddr( $normalized_ip );
		if ( ! is_string( $hostname ) || '' === $hostname || $hostname === $normalized_ip ) {
			return false;
		}

		$hostname = rtrim( trim( strtolower( $hostname ) ), '.' );
		if ( preg_match( '/' . $domain_pattern . '$/i', $hostname ) ) {
			$resolved_ips = array();
			if ( function_exists( 'dns_get_record' ) ) {
				$records = dns_get_record( $hostname, DNS_A | DNS_AAAA );
				if ( is_array( $records ) ) {
					foreach ( $records as $record ) {
						if ( isset( $record['ip'] ) ) {
							$resolved_ips[] = $record['ip'];
						} elseif ( isset( $record['ipv6'] ) ) {
							$resolved_ips[] = $record['ipv6'];
						}
					}
				}
			}

			if ( array() === $resolved_ips ) {
				$hosts = gethostbynamel( $hostname );
				if ( is_array( $hosts ) ) {
					$resolved_ips = $hosts;
				}
			}

			foreach ( $resolved_ips as $host ) {
				if ( $normalized_ip === $this->normalize_ip_address( $host ) ) {
					return true;
				}
			}
		}

		return false;
	}
}
