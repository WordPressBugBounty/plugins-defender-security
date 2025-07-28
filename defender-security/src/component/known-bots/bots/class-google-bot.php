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
class Google_Bot implements Bots_Interface {
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
}
