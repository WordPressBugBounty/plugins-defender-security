<?php
/**
 * Factory class for creating instances of Known_Bots with predefined bot providers.
 *
 * @package WP_Defender\Component\Known_Bots
 */

namespace WP_Defender\Component\Known_Bots;

use WP_Defender\Component\Known_Bots\Bots\Google_Bot;
use WP_Defender\Component\Known_Bots\Bots\Bing_Bot;

/**
 * Factory class to create a Known_Bots instance with predefined bot providers.
 *
 * This class encapsulates the creation logic for Known_Bots, allowing for easy instantiation
 * with a set of known bot providers.
 */
class Known_Bots_Factory {
	/**
	 * Creates an instance of Known_Bots with predefined bot providers.
	 *
	 * @return Known_Bots An instance of Known_Bots containing Google_Bot and Bing_Bot.
	 */
	public static function create(): Known_Bots {
		return new Known_Bots(
			array(
				new Google_Bot(),
				new Bing_Bot(),
			)
		);
	}
}
