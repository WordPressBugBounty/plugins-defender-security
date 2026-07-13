<?php
/**
 * Notification component stub for free version.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Model\Notification\Audit_Report;
use WP_Defender\Model\Notification\Malware_Report;
use WP_Defender\Model\Notification\Tweak_Reminder;
use WP_Defender\Model\Notification\Firewall_Report;
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
	 * Get all non-pro modules as array of arrays.
	 *
	 * @return array
	 */
	public function get_modules(): array {
		return array(
			Malware_Notification::SLUG  => wd_di()->get( Malware_Notification::class )->export(),
			Firewall_Notification::SLUG => wd_di()->get( Firewall_Notification::class )->export(),
		);
	}

	/**
	 * Get all non-pro modules as array of objects.
	 *
	 * @return array
	 */
	public function get_modules_as_objects(): array {
		return array(
			wd_di()->get( Malware_Notification::class ),
			wd_di()->get( Firewall_Notification::class ),
		);
	}

	/**
	 * Build a slug-to-model index for all notification modules.
	 *
	 * @return array<string, \WP_Defender\Model\Notification>
	 */
	public function get_module_map(): array {
		$map = array();
		foreach ( $this->get_modules_as_objects() as $model ) {
			$map[ $model->slug ] = $model;
		}

		return $map;
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
	 * Get the alert model (firewall notification).
	 *
	 * @return array
	 */
	public function get_alert_model(): array {
		return array( Firewall_Notification::SLUG => wd_di()->get( Firewall_Notification::class )->export() );
	}

	/**
	 * Get all report models keyed by slug. Only for the view.
	 *
	 * @return array
	 */
	public function get_reports_model(): array {
		$malware_report             = wd_di()->get( Malware_Report::class )->export();
		$malware_report['ui_title'] = esc_html__( 'Issues', 'defender-security' );

		$tweak_reminder             = wd_di()->get( Tweak_Reminder::class )->export();
		$tweak_reminder['ui_title'] = esc_html__( 'Hardening', 'defender-security' );

		$firewall_report             = wd_di()->get( Firewall_Report::class )->export();
		$firewall_report['ui_title'] = esc_html__( 'Firewall', 'defender-security' );

		$audit_report             = wd_di()->get( Audit_Report::class )->export();
		$audit_report['ui_title'] = esc_html__( 'Audit log', 'defender-security' );

		return array(
			Malware_Report::SLUG  => $malware_report,
			Tweak_Reminder::SLUG  => $tweak_reminder,
			Firewall_Report::SLUG => $firewall_report,
			Audit_Report::SLUG    => $audit_report,
		);
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
	 * Dispatches reports.
	 */
	public function maybe_dispatch_report() {
		// No Pro reports.
	}
}
