<?php
/**
 * Handles Google Bot IPs.
 *
 * @package WP_Defender\Component\Known_Bots\Bots
 */

namespace WP_Defender\Component\Known_Bots\Bots;

/**
 * This class is responsible for fetching and managing Google Bot IPs.
 */
class Google_Bot extends Abstract_Bot {
	/**
	 * Returns the name of the bot.
	 *
	 * @return string The name of the bot.
	 */
	public function get_name(): string {
		return 'googlebot';
	}

	/**
	 * Fetches the IPs for Google Bot.
	 *
	 * This method retrieves the IP ranges used by Google Bot from a remote JSON endpoint.
	 * It returns an array of IP addresses in both IPv4 and IPv6 formats.
	 *
	 * @return array An array of IP addresses used by Google Bot.
	 */
	public function fetch_ips(): array {
		$url = 'https://developers.google.com/static/search/apis/ipranges/googlebot.json';
		$ips = array();

		$response = wp_remote_get( $url );
		if ( is_array( $response ) && ! is_wp_error( $response ) ) {
			$data = json_decode( wp_remote_retrieve_body( $response ), true );
			foreach ( $data['prefixes'] ?? array() as $entry ) {
				if ( isset( $entry['ipv4Prefix'] ) ) {
					$ips[] = $entry['ipv4Prefix'];
				}

				if ( isset( $entry['ipv6Prefix'] ) ) {
					$ips[] = $entry['ipv6Prefix'];
				}
			}
		}

		return $ips;
	}

	/**
	 * Checks if the user agent belongs to Google.
	 *
	 * @param string $user_agent Optional user agent string to check.
	 *
	 * @return bool
	 */
	public function is_ua( string $user_agent = '' ): bool {
		$ua = $this->normalize_ua( $user_agent );
		if ( '' === $ua ) {
			return false;
		}

		return false !== stristr( $ua, 'googlebot' );
	}

	/**
	 * Checks if IP is from Google, based on DNS verification.
	 *
	 * @param string $ip The IP address to check.
	 *
	 * @return bool
	 */
	public function is_ip( string $ip ): bool {
		return $this->verify_dns( $ip, '(^|\.)(googlebot\.com|google\.com)' );
	}
}
