<?php
/**
 * Notification component stub for free version.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Model\Notification\Tweak_Reminder;
use WP_Defender\Model\Notification\Malware_Notification;
use WP_Defender\Model\Notification\Firewall_Notification;

/**
 * Notification component.
 */
class Notification extends Notification_Base {

	/**
	 * Constructs the Notification component.
	 */
	public function __construct() {
		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
	}

	/**
	 * Get all non-pro modules.
	 *
	 * @return array
	 */
	public function get_modules(): array {
		return array(
			wd_di()->get( Tweak_Reminder::class )->export(),
			wd_di()->get( Malware_Notification::class )->export(),
			wd_di()->get( Firewall_Notification::class )->export(),
		);
	}

	/**
	 * Get all non-pro modules as array of objects.
	 *
	 * @return array
	 */
	public function get_modules_as_objects(): array {
		return array(
			wd_di()->get( Tweak_Reminder::class ),
			wd_di()->get( Malware_Notification::class ),
			wd_di()->get( Firewall_Notification::class ),
		);
	}

	/**
	 * Return the time that the next report will be triggered. For free always return 'Never'.
	 *
	 * @return string
	 */
	public function get_next_run() {
		return esc_html__( 'Never', 'defender-security' );
	}

	/**
	 * Get inactive modules. For free it's always empty.
	 *
	 * @return array
	 */
	public function get_inactive_modules(): array {
		return array();
	}

	/**
	 * Get active pro report modules as arrays. For free it's always empty.
	 *
	 * @return array
	 */
	public function get_active_pro_reports(): array {
		return array();
	}

	/**
	 * Get active pro report modules as objects. For free it's always empty.
	 *
	 * @return array
	 */
	public function get_active_pro_reports_as_objects(): array {
		return array();
	}

	/**
	 * Dispatches reports. For free only dispatch Tweak_Reminder reports.
	 */
	public function maybe_dispatch_report() {
		$module = wd_di()->get( Tweak_Reminder::class );
		if ( $module->maybe_send() ) {
			$module->send();
		}
	}
}
