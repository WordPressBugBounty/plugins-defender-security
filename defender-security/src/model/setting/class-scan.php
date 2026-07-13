<?php
/**
 * Handles scan settings.
 *
 * @package WP_Defender\Model\Setting
 */

namespace WP_Defender\Model\Setting;

use Calotes\Model\Setting;

/**
 * Model for scan settings.
 */
class Scan extends Setting {

	/**
	 * Option name.
	 *
	 * @var string
	 */
	protected $table = 'wd_scan_settings';

	/**
	 * Enable core/plugin integrity check while perform a scan.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $integrity_check = true;

	/**
	 * Enable Scan WP core files.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $check_core = true;

	/**
	 * Enable Scan plugin files.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $check_plugins = true;

	/**
	 * Check the files inside wp-content by our malware signatures.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $scan_malware = true;

	/**
	 * Check if any plugins or themes have a known vulnerability.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $check_known_vuln = true;

	/**
	 * If a file is smaller than this, we wil include it to the test.
	 *
	 * @defender_property
	 * @var int
	 */
	public $filesize = 10;

	/**
	 * Is scheduled scanning enabled?
	 *
	 * @var bool
	 * @defender_property
	 */
	public $scheduled_scanning = false;

	/**
	 * The frequency of scheduled scan.
	 *
	 * @var string
	 * @defender_property
	 * @rule in[daily,weekly,monthly]
	 */
	public $frequency = 'weekly';

	/**
	 * The day of scheduled scan.
	 *
	 * @var string
	 * @defender_property
	 * @sanitize_text_field
	 */
	public $day = '';

	/**
	 * This is for when user select scheduled scan as monthly, we will have the day number, instead of text.
	 *
	 * @var int
	 * @sanitize_text_field
	 * @defender_property
	 */
	public int $day_n = 1;

	/**
	 * Same as $day.
	 *
	 * @var string
	 * @defender_property
	 * @sanitize_text_field
	 */
	public $time = '';

	/**
	 * Quarantine file deletion/expiration cron schedule.
	 *
	 * @var string
	 * @defender_property
	 * @sanitize_text_field
	 */
	public $quarantine_expire_schedule = 'thirty_days';

	/**
	 * Enable Abandoned or outdated plugins.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $check_abandoned_plugin = true;

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return array(
			'integrity_check'        => esc_html__( 'File change detection', 'defender-security' ),
			'check_core'             => esc_html__( 'Scan core files', 'defender-security' ),
			'check_plugins'          => esc_html__( 'Scan plugin files', 'defender-security' ),
			'check_abandoned_plugin' => esc_html__( 'Outdated & removed plugins', 'defender-security' ),
			'check_known_vuln'       => esc_html__( 'Known vulnerabilities', 'defender-security' ),
			'scan_malware'           => esc_html__( 'Suspicious code', 'defender-security' ),
			'filesize'               => esc_html__( 'Max included file size', 'defender-security' ),
			'scheduled_scanning'     => esc_html__( 'Scheduled Scanning', 'defender-security' ),
			'frequency'              => esc_html__( 'Frequency', 'defender-security' ),
			'day'                    => esc_html__( 'Day of the week', 'defender-security' ),
			'day_n'                  => esc_html__( 'Day of the month', 'defender-security' ),
			'time'                   => esc_html__( 'Time of day', 'defender-security' ),
		);
	}

	/**
	 * Check different cases for 'File change detection' option.
	 *
	 * @return bool
	 */
	public function is_checked_any_file_change_types(): bool {
		if ( ! $this->integrity_check ) {
			// Check the parent type.
			return false;
		} elseif ( $this->integrity_check && ! $this->check_core && ! $this->check_plugins ) {
			// Check the parent and child types.
			return false;
		}

		return true;
	}

	/**
	 * Validates the input after form submission and adds error messages if necessary.
	 *
	 * @return void
	 */
	protected function after_validate(): void {
		// Case#1: all child types of File change detection are unchecked BUT the parent type is checked.
		if ( $this->integrity_check && ! $this->check_core && ! $this->check_plugins ) {
			$this->errors[] = sprintf(
				/* translators: %s: File change detection. */
				esc_html__( 'You have not selected a scan type for the %s. Please choose at least one and save the settings again.', 'defender-security' ),
				'<strong>' . esc_html__( 'File change detection', 'defender-security' ) . '</strong>'
			);
			// Case#2: all scan types are unchecked.
		} elseif ( ! $this->is_enabled_any_scan_type() ) {
			$this->errors[] = esc_html__(
				'You have not selected a scan type. Please enable at least one scan type and save the settings again.',
				'defender-security'
			);
		}
	}

	/**
	 * Initializes the object by setting default values.
	 *
	 * @return void
	 */
	protected function before_load(): void {
	}

	/**
	 * Is enabled any scan type at least?
	 *
	 * @return bool
	 */
	private function is_enabled_any_scan_type(): bool {
		return $this->integrity_check
			|| $this->check_known_vuln
			|| $this->scan_malware
			|| $this->check_abandoned_plugin;
	}

	/**
	 * Is enabled Scheduled Scanning?
	 *
	 * @return bool
	 */
	public function is_enabled_scheduled_scanning(): bool {
		return false;
	}
}
