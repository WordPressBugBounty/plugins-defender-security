<?php
/**
 * Abstract base class for free-version report stubs.
 *
 * @package WP_Defender\Model\Notification
 */

namespace WP_Defender\Model\Notification;

/**
 * Abstract base class for free-version report stubs.
 */
abstract class Free_Report extends \WP_Defender\Model\Notification {

	/**
	 * Returns the default fields shared by all report notifications.
	 *
	 * @return array
	 */
	protected function base_defaults(): array {
		return array(
			'status'               => self::STATUS_DISABLED,
			'in_house_recipients'  => array(),
			'out_house_recipients' => array(),
			'type'                 => 'report',
			'frequency'            => 'weekly',
			'day'                  => 'sunday',
			'day_n'                => 1,
			'time'                 => '4:00',
			'dry_run'              => false,
			'configs'              => array(),
		);
	}

	/**
	 * Never dispatches a report in the free version.
	 *
	 * @return bool Always false.
	 */
	public function maybe_send(): bool {
		return false;
	}

	/**
	 * No-op: report sending is a Pro-only feature.
	 */
	public function send(): void {}

	/**
	 * Additional converting rules.
	 *
	 * @param array $configs The configuration data.
	 *
	 * @return array The type-casted configuration data.
	 */
	public function type_casting( $configs ): array {
		return is_array( $configs ) ? $configs : array();
	}
}
