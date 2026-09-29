<?php
/**
 * Handles Facebook Bot IPs.
 *
 * @package WP_Defender\Component\Known_Bots\Bots
 */

namespace WP_Defender\Component\Known_Bots\Bots;

/**
 * This class is responsible for fetching and managing Facebook Bot IPs.
 */
class Facebook_Bot extends Abstract_Bot {
	/**
	 * API endpoints to query for IP info.
	 *
	 * @var string[]
	 */
	public const IP_INFO_SERVICES = array(
		'https://ipinfo.io/%s/json',
		'https://ipwho.is/%s',
		'http://ip-api.com/json/%s',
	);

	/**
	 * Prefix for site transient cache keys.
	 *
	 * @var string
	 */
	public const FB_CACHE_KEY_PREFIX = 'wpdef_ip_is_fb_';

	/**
	 * Cache lifetimes.
	 */
	public const FB_CACHE_TTL_CONFIRMED   = WEEK_IN_SECONDS;
	public const FB_CACHE_TTL_UNCONFIRMED = HOUR_IN_SECONDS;

	/**
	 * Returns the name of the bot.
	 *
	 * @return string The name of the bot.
	 */
	public function get_name(): string {
		return 'facebookbot';
	}

	/**
	 * Fetches the IPs for Facebook Bot.
	 *
	 * This method retrieves the announced IP ranges for Meta/Facebook (AS32934 and AS63293) from RIPEstat.
	 * It returns an array of IP addresses in both IPv4 and IPv6 CIDR formats.
	 *
	 * @return array An array of IP addresses used by Facebook Bot.
	 */
	public function fetch_ips(): array {
		$asns = array( 'AS32934', 'AS63293' );
		$ips  = array();

		foreach ( $asns as $asn ) {
			$url      = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={$asn}";
			$response = wp_remote_get( $url, array( 'timeout' => 5 ) );

			if ( is_array( $response ) && ! is_wp_error( $response ) ) {
				$data = json_decode( wp_remote_retrieve_body( $response ), true );
				foreach ( $data['data']['prefixes'] ?? array() as $entry ) {
					if ( isset( $entry['prefix'] ) && is_string( $entry['prefix'] ) ) {
						$ips[] = $entry['prefix'];
					}
				}
			}
		}

		return array_unique( $ips );
	}

	/**
	 * Checks if the user agent belongs to Facebook.
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

		return (bool) preg_match( '/facebookexternalhit|facebot|facebookcatalog|meta-(externalagent|externalads|externalfetcher|webindexer)/i', $ua );
	}

	/**
	 * Determines if the request User-Agent belongs to Apple iMessage link preview.
	 *
	 * Apple iMessage uses a full browser UA containing AppleWebKit, Safari, Facebot,
	 * facebookexternalhit, and Twitterbot to fetch link preview metadata directly
	 * from consumer device IPs. It does not use Meta crawler URLs.
	 *
	 * @param string $user_agent Optional user agent string.
	 * @return bool
	 */
	public function is_imessage_ua( string $user_agent = '' ): bool {
		$ua = $this->normalize_ua( $user_agent );
		if ( '' === $ua ) {
			return false;
		}

		// Must contain both preview substrings.
		if ( false === stripos( $ua, 'facebookexternalhit' ) || false === stripos( $ua, 'twitterbot' ) ) {
			return false;
		}

		// Must not be a Facebook crawler URL pattern (attacker trying to forge preview tokens).
		if ( false !== stripos( $ua, 'facebook.com/externalhit' ) ) {
			return false;
		}

		// Apple iMessage always contains Safari or WebKit browser tokens.
		return false !== stripos( $ua, 'applewebkit' ) || false !== stripos( $ua, 'safari' );
	}

	/**
	 * Checks if IP is from Facebook, based on cache, IP prefix allowlist,
	 * DNS verification, and external IP info services.
	 *
	 * @param string $ip The IP address to check.
	 *
	 * @return bool
	 */
	public function is_ip( string $ip ): bool {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		// Legitimate Apple iMessage preview clients originate from consumer IPs, not Meta data centers.
		if ( $this->is_imessage_ua() ) {
			return true;
		}

		$cache_key = self::FB_CACHE_KEY_PREFIX . md5( $ip );

		$cached = get_site_transient( $cache_key );
		if ( false !== $cached ) {
			return (bool) $cached;
		}

		// 1. Check announced Meta IP prefix allowlist (AS32934 / AS63293).
		$allowed_ips = get_site_transient( 'wpdef_known_bot_ips_' . $this->get_name() );
		if ( ! is_array( $allowed_ips ) || array() === $allowed_ips ) {
			$allowed_ips = $this->fetch_ips();
			if ( array() !== $allowed_ips ) {
				set_site_transient( 'wpdef_known_bot_ips_' . $this->get_name(), $allowed_ips, DAY_IN_SECONDS );
			}
		}

		if ( array() !== $allowed_ips && $this->is_ip_in_format( $ip, $allowed_ips ) ) {
			set_site_transient( $cache_key, 1, self::FB_CACHE_TTL_CONFIRMED );

			return true;
		}

		// 2. Forward-confirmed reverse DNS (FCrDNS) check.
		if ( $this->verify_dns( $ip, '(^|\.)(facebook\.com|fbsv\.net|fbcdn\.net)' ) ) {
			set_site_transient( $cache_key, 1, self::FB_CACHE_TTL_CONFIRMED );

			return true;
		}

		// 3. Fallback to external IP info services.
		$is_fb = $this->query_ip_info_services( $ip );

		set_site_transient(
			$cache_key,
			$is_fb ? 1 : 0,
			$is_fb ? self::FB_CACHE_TTL_CONFIRMED : self::FB_CACHE_TTL_UNCONFIRMED
		);

		return $is_fb;
	}

	/**
	 * Queries external IP information services to verify whether an IP belongs to Facebook/Meta.
	 *
	 * @param string $ip The IP address to check.
	 *
	 * @return bool
	 */
	private function query_ip_info_services( string $ip ): bool {
		foreach ( self::IP_INFO_SERVICES as $endpoint ) {
			$url = sprintf( $endpoint, $ip );

			$response = wp_remote_get(
				$url,
				array(
					'timeout' => 3,
					'headers' => array( 'Accept' => 'application/json' ),
				)
			);

			if ( is_wp_error( $response ) ) {
				continue;
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			if ( ! is_array( $data ) ) {
				continue;
			}

			$org = $data['org'] ?? $data['connection']['org'] ?? null;
			$isp = $data['isp'] ?? $data['connection']['isp'] ?? null;

			if (
				preg_match( '/facebook|meta/i', (string) ( $org ?? '' ) ) ||
				preg_match( '/facebook|meta/i', (string) ( $isp ?? '' ) )
			) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Clear all Facebook IP check transients.
	 */
	public function clear_fb_transients(): void {
		global $wpdb;

		$cache_key       = self::FB_CACHE_KEY_PREFIX;
		$like_pattern    = "_site_transient_{$cache_key}%";
		$timeout_pattern = "_site_transient_timeout_{$cache_key}%";

		if ( is_multisite() ) {
			$table      = $wpdb->sitemeta;
			$key_column = 'meta_key';
		} else {
			$table      = $wpdb->options;
			$key_column = 'option_name';
		}

		// Delete Facebook IP check transients.
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE {$key_column} LIKE %s OR {$key_column} LIKE %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$like_pattern,
				$timeout_pattern
			)
		);

		if ( function_exists( 'wp_cache_flush' ) ) {
			wp_cache_flush();
		}
	}
}
