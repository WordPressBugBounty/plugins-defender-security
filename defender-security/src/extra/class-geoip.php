<?php
/**
 * GeoIP functionality for WP Defender.
 *
 * @package WP_Defender\Extra
 */

namespace WP_Defender\Extra;

use MaxMind\Db\Reader;

/**
 * GeoIP class for IP geolocation functionality.
 */
class GeoIp {
	/**
	 * MaxMind database reader instance.
	 *
	 * @var Reader
	 */
	protected $provider;

	/**
	 * Constructor.
	 *
	 * @param string $db_path Path to the MaxMind database file.
	 */
	public function __construct( $db_path ) {
		$this->provider = new Reader( $db_path );
	}

	/**
	 * Convert IP address to country information.
	 *
	 * @param string $ip IP address to lookup.
	 *
	 * @return array<string, string>|false Country data array with 'iso' and 'name' keys, or false on failure.
	 * @throws Reader\InvalidDatabaseException When database format is invalid.
	 */
	public function ip_to_country( $ip ) {
		$info = $this->provider->get( $ip );

		// Try country first, then fall back to registered_country.
		$country_data = null;
		if ( isset( $info['country'] ) && is_array( $info['country'] ) ) {
			$country_data = $info['country'];
		} elseif ( isset( $info['registered_country'] ) && is_array( $info['registered_country'] ) ) {
			$country_data = $info['registered_country'];
		}

		if ( null === $country_data ) {
			return false;
		}

		return array(
			'iso'  => $country_data['iso_code'] ?? '',
			'name' => $country_data['names']['en'] ?? '',
		);
	}
}
