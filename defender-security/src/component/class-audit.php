<?php
/**
 * Simple functionality.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;

/**
 * Simple methods.
 */
class Audit extends Component {

	public const AUDIT_LOG             = 'audit.log';
	public const CACHE_LAST_CHECKPOINT = 'wd_audit_fetch_checkpoint';

	/**
	 * Dummy.
	 *
	 * @param  int    $date_from  Start date for fetching logs.
	 * @param  int    $date_to  End date for fetching logs.
	 * @param  array  $events  Specific events to fetch.
	 * @param  string $user_id  User ID to filter logs.
	 * @param  string $ip  IP address to filter logs.
	 * @param  int    $paged  Pagination page number.
	 *
	 * @return array
	 */
	public function fetch( $date_from, $date_to, $events = array(), $user_id = '', $ip = '', $paged = 1 ) {
		return array();
	}

	/**
	 * Dummy.
	 */
	public function flush() {
	}

	/**
	 * Dummy.
	 */
	public function audit_clean_up_logs() {
	}

	/**
	 * Dummy.
	 */
	public function enqueue_event_listener() {
	}

	/**
	 * Dummy.
	 */
	public function log_audit_events() {
	}
}
