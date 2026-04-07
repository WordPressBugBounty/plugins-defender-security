<?php
/**
 * Handles fake bot detection functionality (Free version stub).
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;

/**
 * Stub class for fake bot detection functionality in the Free version.
 * This feature is only available in the Pro version.
 */
class Fake_Bot_Detection extends Component {
	/**
	 * Shared scenario slug used across lockout and breadcrumbs cleanup flows.
	 */
	public const SCENARIO_FAKE_BOT = 'fake_bot';

	/**
	 * Constructor for the Fake_Bot_Detection class.
	 * Does nothing in the Free version.
	 *
	 * @param mixed $model Unused in Free version.
	 */
	public function __construct( $model = null ) {
	}

	/**
	 * Check if the fake bot detection is enabled.
	 *
	 * @return bool Always false in Free version.
	 */
	public function is_enabled(): bool {
		return false;
	}

	/**
	 * Determine if the current HTTP request is from a legitimate crawler.
	 * Does nothing in the Free version.
	 */
	public function validate_legit_crawler(): void {
	}

	/**
	 * Load crawler definitions from remote URL with local fallback.
	 * Does nothing in the Free version.
	 */
	public function load_crawlers(): void {
	}

	/**
	 * Log the event into db.
	 * Does nothing in the Free version.
	 *
	 * @param  string $ip        The IP address involved in the event.
	 * @param  string $scenario  The scenario under which the event is logged.
	 * @param  string $bot_name  The name of the bot being impersonated.
	 */
	public function log_event( $ip, $scenario, $bot_name ) {
	}

	/**
	 * Clear all Facebook IP check transients.
	 * Does nothing in the Free version.
	 */
	public function clear_fb_transients(): void {
	}
}
