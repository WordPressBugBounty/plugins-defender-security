<?php
/**
 * Base behavior class.
 *
 * @package Calotes\Component
 */

namespace Calotes\Component;

use Calotes\Base\Component;

/**
 * Base behavior class for all behaviors.
 */
class Behavior extends Component {

	/**
	 * The component this behavior tied to.
	 *
	 * @var object
	 */
	public $owner;

	/**
	 * Get a failed ignore result.
	 *
	 * @param string $issue_name Name of scan issue.
	 *
	 * @return string
	 */
	public function get_failed_ignore_result( string $issue_name ): string {
		return sprintf(
			/* translators: %s: Scan issue name. */
			esc_html__( '%s is already marked as Ignored. It can’t be added to the Ignored list again.', 'defender-security' ),
			$issue_name
		);
	}

	/**
	 * Get a failed restore result.
	 *
	 * @param string $issue_name Name of scan issue.
	 *
	 * @return string
	 */
	public function get_failed_restore_result( string $issue_name ): string {
		return sprintf(
			/* translators: %s: Scan issue name. */
			esc_html__( '%s is already marked as Issue. It can’t be added to the Issue list again.', 'defender-security' ),
			$issue_name
		);
	}

	/**
	 * Get issue name.
	 *
	 * @param array $raw_data Array of raw data.
	 *
	 * @return string
	 */
	public function get_issue_name( $raw_data ): string {
		return $raw_data['name'];
	}
}
