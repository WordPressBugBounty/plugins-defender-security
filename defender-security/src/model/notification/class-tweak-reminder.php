<?php
/**
 * Handles the notification of security recommendations that need fixing.
 *
 * @package WP_Defender\Model\Notification
 */

namespace WP_Defender\Model\Notification;

use DateTime;
use Countable;
use Exception;
use DateInterval;
use DI\DependencyException;
use Calotes\Helper\Array_Cache;
use WP_Defender\Component\Mail;
use WP_Defender\Component\Notification;
use WP_Defender\Controller\Security_Tweaks;

/**
 * Handles the notification of security recommendations that need fixing.
 */
class Tweak_Reminder extends \WP_Defender\Model\Notification {

	/**
	 * Table name.
	 *
	 * @var string
	 */
	protected $table = 'wd_security_tweaks_reminder';
	/**
	 * Slug identifier for the tweak reminder.
	 *
	 * @var string
	 */
	public const SLUG = 'tweak-reminder';

	/**
	 * Constructor method.
	 * Sets default values for the class.
	 */
	protected function before_load(): void {
		$params = array(
			'slug'                 => self::SLUG,
			'title'                => esc_html__( 'Hardening - Alert', 'defender-security' ),
			'status'               => self::STATUS_DISABLED,
			'description'          => esc_html__(
				'Get email alerts if/when a hardening item needs fixing.',
				'defender-security'
			),
			// @since 3.0.0 Fix 'Guest'-line.
			'in_house_recipients'  => array(),
			'out_house_recipients' => array(),
			'type'                 => 'report',
			'frequency'            => 'weekly',
			'day'                  => 'sunday',
			'day_n'                => 1,
			'time'                 => '4:00',
			'est_timestamp'        => 0,
			'dry_run'              => false,
			'configs'              => array(
				'reminder' => 'weekly',
			),
		);
		$this->import( $params );
	}

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return array(
			'notification'        => esc_html__( 'Hardening - Alert', 'defender-security' ),
			'notification_repeat' => esc_html__( 'Frequency', 'defender-security' ),
			'subscribers'         => esc_html__( 'Recipients', 'defender-security' ),
		);
	}

	/**
	 * Additional converting rules.
	 *
	 * @param  array $configs  The configuration data.
	 *
	 * @return array The type-casted configuration data.
	 * @since 3.1.0
	 */
	public function type_casting( $configs ): array {
		return is_array( $configs ) ? $configs : array();
	}

	/**
	 * Normalizes tweak reminder data after loading.
	 */
	protected function after_load(): void {
		parent::after_load();
		$this->title = esc_html__( 'Hardening report', 'defender-security' );
	}
}
