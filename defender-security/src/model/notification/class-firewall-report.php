<?php
/**
 * Firewall report notification stub for free version.
 *
 * @package WP_Defender\Model\Notification
 */

namespace WP_Defender\Model\Notification;

/**
 * Firewall – Reporting.
 */
class Firewall_Report extends Free_Report {

	/**
	 * Table name.
	 *
	 * @var string
	 */
	protected $table = 'wd_lockout_report';

	/**
	 * Slug identifier for the firewall report.
	 *
	 * @var string
	 */
	public const SLUG = 'firewall-report';

	/**
	 * Sets default values.
	 */
	protected function before_load(): void {
		$this->import(
			array_merge(
				$this->base_defaults(),
				array(
					'slug'        => self::SLUG,
					'title'       => esc_html__( 'Firewall - Reporting', 'defender-security' ),
					'description' => esc_html__(
						'Configure Defender to automatically email you a lockout report for this website.',
						'defender-security'
					),
				)
			)
		);
	}

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return array(
			'report'             => esc_html__( 'Firewall - Reporting', 'defender-security' ),
			'day'                => esc_html__( 'Day of', 'defender-security' ),
			'day_n'              => esc_html__( 'Day of', 'defender-security' ),
			'report_time'        => esc_html__( 'Time of day', 'defender-security' ),
			'report_frequency'   => esc_html__( 'Frequency', 'defender-security' ),
			'report_subscribers' => esc_html__( 'Recipients', 'defender-security' ),
		);
	}

}
