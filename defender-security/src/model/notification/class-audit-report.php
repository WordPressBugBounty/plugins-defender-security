<?php
/**
 * Audit Report notification model.
 *
 * @package WP_Defender\Model\Notification
 */

namespace WP_Defender\Model\Notification;

/**
 * Audit Report notification model.
 */
class Audit_Report extends Free_Report {

	/**
	 * Table name.
	 *
	 * @var string
	 */
	protected $table = 'wd_audit_report';

	/**
	 * Slug identifier for the audit report.
	 *
	 * @var string
	 */
	public const SLUG = 'audit-report';

	/**
	 * Sets default values.
	 */
	protected function before_load(): void {
		$this->import(
			array_merge(
				$this->base_defaults(),
				array(
					'slug'        => self::SLUG,
					'title'       => esc_html__( 'Audit Logging - Reporting', 'defender-security' ),
					'description' => esc_html__(
						'Schedule Defender to automatically email you a summary of all your website events.',
						'defender-security'
					),
				)
			)
		);
	}

	/**
	 * Define labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return array(
			'report'      => esc_html__( 'Audit Logging - Reporting', 'defender-security' ),
			'subscribers' => esc_html__( 'Recipients', 'defender-security' ),
			'day'         => esc_html__( 'Day of', 'defender-security' ),
			'day_n'       => esc_html__( 'Day of', 'defender-security' ),
			'time'        => esc_html__( 'Time of day', 'defender-security' ),
			'frequency'   => esc_html__( 'Frequency', 'defender-security' ),
		);
	}

}
