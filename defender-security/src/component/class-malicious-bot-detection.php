<?php
/**
 * Handles malicious bot functionality (Free version stub).
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;

/**
 * Stub class for malicious bot functionality in the Free version.
 * This feature is only available in the Pro version.
 */
class Malicious_Bot extends Component {

	/**
	 * Constructor for the Malicious_Bot class.
	 * Does nothing in the Free version.
	 *
	 * @param mixed $model Unused in Free version.
	 */
	public function __construct( $model = null ) {
	}

	/**
	 * Check if the malicious bot is enabled.
	 *
	 * @return bool Always false in Free version.
	 */
	public function is_enabled(): bool {
		return false;
	}

	/**
	 * Get the hash for the malicious bot URL.
	 *
	 * @return false Always false in Free version.
	 */
	public function get_hash() {
		return false;
	}

	/**
	 * Rotate the hash for the malicious bot URL.
	 * Does nothing in the Free version.
	 */
	public function rotate_hash() {
	}

	/**
	 * Handle the robots.txt rule.
	 * Does nothing in the Free version.
	 */
	public function handle_robots_txt() {
	}

	/**
	 * Detect if there's an empty Disallow line in robots.txt.
	 *
	 * @return bool Always false in Free version.
	 */
	public function has_empty_disallow_line(): bool {
		return false;
	}

	/**
	 * Registers a rewrite rule for the malicious bot URL.
	 * Does nothing in the Free version.
	 */
	public function register_rewrite_rule() {
	}

	/**
	 * Remove the bot trap rule from the robots.txt.
	 * Does nothing in the Free version.
	 */
	public function remove_rule() {
	}

	/**
	 * Log the event into db.
	 * Does nothing in the Free version.
	 *
	 * @param  string $ip  The IP address involved in the event.
	 * @param  string $uri  The URI that was accessed.
	 * @param  string $scenario  The scenario under which the event is logged.
	 */
	public function log_event( $ip, $uri, $scenario ) {
	}

	/**
	 * Creates a lockout for a blocked IP.
	 * Does nothing in the Free version.
	 *
	 * @param  mixed  $model    The lockout IP model.
	 * @param  string $message  The lockout message.
	 * @param  int    $time     The timestamp when the lockout will be lifted.
	 */
	public function create_blocked_lockout( &$model, $message, $time ) {
	}
}
