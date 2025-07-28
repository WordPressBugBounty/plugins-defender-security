<?php
/**
 * Responsible for handling known bot IPs.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component\Known_Bots;

use WP_Defender\Component\Known_Bots\Bots\Bots_Interface;

/**
 * This class is responsible for managing known bot IPs.
 * It fetches and caches the IPs from various providers.
 */
class Known_Bots {
	/**
	 * An array of bot providers that implement the Bots_Interface.
	 *
	 * @var Bots_Interface[]
	 */
	protected $providers = array();

	/**
	 * Constructor for the Known_Bots class.
	 *
	 * @param Bots_Interface[] $providers An array of bot providers that implement the Bots_Interface.
	 */
	public function __construct( array $providers = array() ) {
		$this->providers = $providers;
	}

	/**
	 * Fetches all known bot IPs from the registered providers.
	 *
	 * @return array An associative array where keys are provider names and values are arrays of IPs.
	 */
	public function get_all_bot_ips(): array {
		$data = array();

		foreach ( $this->providers as $provider ) {
			if ( $provider instanceof Bots_Interface ) {
				$name          = $provider->get_name();
				$data[ $name ] = $this->get_or_set_bot_ips( $provider );
			}
		}

		return $data;
	}

	/**
	 * Fetches and caches bot IPs for a specific provider.
	 *
	 * @param Bots_Interface $provider The bot provider to fetch IPs from.
	 *
	 * @return array An array of bot IPs.
	 */
	protected function get_or_set_bot_ips( Bots_Interface $provider ): array {
		$transient_key = 'wpdef_known_bot_ips_' . $provider->get_name();
		$cached        = get_site_transient( $transient_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$ips = $provider->fetch_ips();
		set_site_transient( $transient_key, $ips, DAY_IN_SECONDS );

		return $ips;
	}

	/**
	 * Retrieves bot IPs by provider name.
	 *
	 * @param string $name The name of the bot provider.
	 *
	 * @return array An array of bot IPs for the specified provider.
	 */
	public function get_bot_ips_by_name( string $name ): array {
		$key = 'wpdef_known_bot_ips_' . $name;
		$ips = get_site_transient( $key );

		return ! empty( $ips ) ? $ips : array();
	}
}
