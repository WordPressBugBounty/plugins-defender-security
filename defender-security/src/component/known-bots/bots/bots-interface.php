<?php
/**
 * The interface for bots class.
 *
 * @package    WP_Defender\Component\Known_Bots\Bots
 */

namespace WP_Defender\Component\Known_Bots\Bots;

interface Bots_Interface {
	/**
	 * Returns the name of the bot.
	 *
	 * @return string The name of the bot.
	 */
	public function get_name(): string;

	/**
	 * Fetches the IPs for the bot.
	 *
	 * This method retrieves the IP ranges used by the bot from an endpoint.
	 * It returns an array of IP addresses in both IPv4 and IPv6 formats.
	 *
	 * @return array An array of IP addresses used by the bot.
	 */
	public function fetch_ips(): array;

	/**
	 * Checks if the given or current user agent belongs to the bot.
	 *
	 * @param string $user_agent Optional user agent string to check.
	 *
	 * @return bool
	 */
	public function is_ua( string $user_agent = '' ): bool;

	/**
	 * Checks if the given IP belongs to the bot.
	 *
	 * @param string $ip The IP address to check.
	 *
	 * @return bool
	 */
	public function is_ip( string $ip ): bool;
}
