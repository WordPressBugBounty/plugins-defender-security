<?php
/**
 * Handles the scheduling and sending of firewall-related notifications.
 *
 * @package WP_Defender\Model\Notification
 */

namespace WP_Defender\Model\Notification;

use WP_Defender\Traits\IO;
use WP_Defender\Component\Mail;
use WP_Defender\Component\Two_Fa;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Model\Email_Track;
use WP_Defender\Component\Notification;
use WP_Defender\Model\Setting\Login_Lockout;
use WP_Defender\Controller\Blocklist_Monitor;
use WP_Defender\Model\Setting\Notfound_Lockout;
use WP_Defender\Model\Setting\User_Agent_Lockout;

/**
 * Handles the scheduling and sending of firewall-related notifications.
 */
class Firewall_Notification extends \WP_Defender\Model\Notification {

	use IO;

	/**
	 * Table name.
	 *
	 * @var string
	 */
	protected $table = 'wd_malware_firewall_notification';

	/**
	 * Slug identifier for the firewall notification.
	 *
	 * @var string
	 */
	public const SLUG = 'firewall-notification';

	/**
	 * Constructor method.
	 * Sets default values for the class.
	 */
	protected function before_load(): void {
		$default = array(
			'title'                => esc_html__( 'Firewall - Alert', 'defender-security' ),
			'slug'                 => self::SLUG,
			'status'               => self::STATUS_DISABLED,
			'description'          => esc_html__(
				'Get email when a user or IP is locked out for trying to access your login area.',
				'defender-security'
			),
			// @since 3.0.0 Fix 'Guest'-line.
			'in_house_recipients'  => $this->get_default_user(),
			'out_house_recipients' => array(),
			'type'                 => 'notification',
			'dry_run'              => false,
			'configs'              => array(
				'threshold'     => 3,
				'cool_off'      => 24,
				'login_lockout' => true,
				'nf_lockout'    => true,
			),
		);
		$this->import( $default );
	}

	/**
	 * Checks whether the notification options are enabled for the specified lockout log.
	 *
	 * @param  Lockout_Log $model  The lockout log model.
	 *
	 * @return bool True if notification options are enabled; otherwise, false.
	 */
	public function check_options( Lockout_Log $model ): bool {
		if ( self::STATUS_ACTIVE !== $this->status ) {
			return false;
		}
		// Check 'Login Protection Lockout'.
		if ( Lockout_Log::AUTH_LOCK === $model->type ) {
			if ( true === wd_di()->get( Login_Lockout::class )->enabled ) {
				return true;
			}
			return false;
		}
		// Check '404 Protection Lockout'.
		if ( in_array( $model->type, Lockout_Log::get_404_lockout_types(), true ) ) {
			if ( true === wd_di()->get( Notfound_Lockout::class )->enabled ) {
				return true;
			}
			return false;
		}
		// Check 'User Agent Lockout'.
		if ( Lockout_Log::LOCKOUT_UA === $model->type ) {
			if ( true === wd_di()->get( User_Agent_Lockout::class )->enabled ) {
				return true;
			}
			return false;
		}

		return false;
	}

	/**
	 * Constructs and sends the firewall notification email based on the lockout log.
	 *
	 * @param  Lockout_Log $model  The lockout log model.
	 *
	 * @return void
	 */
	public function send( Lockout_Log $model ): void {
		if ( ! $this->check_options( $model ) ) {
			return;
		}

		$template         = $this->get_template( $model );
		$service          = wd_di()->get( Notification::class );
		$network_site_url = network_site_url();
		$email_data       = $this->get_email_data( $model, $template, $network_site_url );
		$headers          = wd_di()->get( Mail::class )->get_headers(
			defender_noreply_email( 'wd_lockout_noreply_email' ),
			self::SLUG
		);
		foreach ( $this->in_house_recipients as $user ) {
			if ( self::USER_SUBSCRIBED !== $user['status'] ) {
				continue;
			}
			$this->send_to_user( $user['email'], $user['name'], $email_data, $headers, $service );
		}

		foreach ( $this->out_house_recipients as $user ) {
			if ( self::USER_SUBSCRIBED !== $user['status'] ) {
				continue;
			}
			$this->send_to_user( $user['email'], $user['name'], $email_data, $headers, $service );
		}
	}

	/**
	 * Gets the email template for the lockout log.
	 *
	 * @param  Lockout_Log $model  The lockout log model.
	 *
	 * @return string The email template key.
	 */
	private function get_template( Lockout_Log $model ): string {
		if ( Lockout_Log::AUTH_LOCK === $model->type ) {
			return 'login-lockout';
		}

		if ( Lockout_Log::LOCKOUT_UA === $model->type ) {
			return 'ua-lockout';
		}

		return 'lockout-404';
	}

	/**
	 * Constructs and sends the email to the specified recipient.
	 *
	 * @param  string $email      The recipient's email address.
	 * @param  string $name       The recipient's name.
	 * @param  array  $email_data Pre-computed email subject and body text.
	 * @param  array  $headers    Pre-computed mail headers.
	 * @param  object $service    The notification service object.
	 *
	 * @return void
	 */
	private function send_to_user(
		string $email,
		string $name,
		array $email_data,
		array $headers,
		object $service
	): void {
		if ( $this->is_email_limit_reached( $email ) ) {
			return;
		}

		$content = $this->render_email_content( $name, $email_data['text'], $email, $service );

		$ret = wp_mail( $email, $email_data['subject'], $content, $headers );
		if ( $ret ) {
			$this->save_log( $email );
		}
	}

	/**
	 * Checks whether the recipient has reached the email notification limit.
	 *
	 * @param  string $email  The recipient's email address.
	 *
	 * @return bool True when the email limit has been reached.
	 */
	private function is_email_limit_reached( string $email ): bool {
		// Handle cool_off period in minutes and hours.
		// The minutes values are in fractional hours, e.g., 0.25 = 15 minutes, 0.5 = 30 minutes.
		$cool_off_seconds = (int) round( (float) $this->configs['cool_off'] * HOUR_IN_SECONDS );
		$count            = Email_Track::count(
			$this->slug,
			$email,
			time() - $cool_off_seconds,
			time()
		);

		return $count >= $this->configs['threshold'];
	}

	/**
	 * Gets email subject and body text for a lockout template.
	 *
	 * @param  Lockout_Log $model  The lockout log model.
	 * @param  string      $template  The email template to use.
	 * @param  string      $network_site_url  The network site URL.
	 *
	 * @return array Email subject and body text.
	 */
	private function get_email_data( Lockout_Log $model, string $template, string $network_site_url ): array {

		if ( 'login-lockout' === $template ) {
			return $this->get_login_lockout_email_data( $model, $network_site_url );
		}

		if ( 'ua-lockout' === $template ) {
			return $this->get_ua_lockout_email_data( $model, $network_site_url );
		}

		return $this->get_404_lockout_email_data( $model, $network_site_url );
	}

	/**
	 * Gets email data for login lockouts.
	 *
	 * @param  Lockout_Log $model  The lockout log model.
	 * @param  string      $network_site_url  The network site URL.
	 *
	 * @return array Email subject and body text.
	 */
	private function get_login_lockout_email_data( Lockout_Log $model, string $network_site_url ): array {
		/* translators: %s: Site URL. */
		$subject = sprintf( esc_html__( 'Login lockout alert for %s', 'defender-security' ), $network_site_url );
		// If the log is made from the 2FA module, then we get the settings from it, otherwise from Login_Lockout.
		$settings = wd_di()->get( Login_Lockout::class );
		if ( false !== strpos( $model->log, '2fa attempts' ) ) {
			$component     = wd_di()->get( Two_Fa::class );
			$attempt_limit = $component->get_attempt_limit();
			$time_limit    = $component->get_time_limit() . esc_html__( ' seconds', 'defender-security' );
			$type          = '2fa';
		} else {
			$attempt_limit = $settings->attempt;
			$time_limit    = $settings->duration . ' ' . $settings->duration_unit;
			$type          = 'login';
		}
		// $text & $string will be escaped at src\view\email\login-lockout.php.
		/* translators: 1: IP address, 2: Site URL, 3: Total attempt from an IP, 4. Lockout type, 5: Translation string. */
		$text = __(
			'The host %1$s has been locked out of %2$s due to more than %3$s failed %4$s attempts. %5$s',
			'defender-security'
		);
		$text = sprintf(
			$text,
			'<strong>' . $model->ip . '</strong>',
			'<a href="' . $network_site_url . '">' . $network_site_url . '</a>',
			'<strong>' . $attempt_limit . '</strong>',
			$type,
			$this->get_lockout_duration_text( $settings->lockout_type, $time_limit )
		);

		return compact( 'subject', 'text' );
	}

	/**
	 * Gets email data for user agent lockouts.
	 *
	 * @param  Lockout_Log $model  The lockout log model.
	 * @param  string      $network_site_url  The network site URL.
	 *
	 * @return array Email subject and body text.
	 */
	private function get_ua_lockout_email_data( Lockout_Log $model, string $network_site_url ): array {
		$subject = sprintf(
			/* translators: %s: Site URL. */
			esc_html__( 'User Agent lockout alert for %s', 'defender-security' ),
			$network_site_url
		);
		$text = sprintf(
			/* translators: 1: User agent, 2: Site URL */
			__( 'The %1$s has been locked out of %2$s.', 'defender-security' ),
			'<strong>' . $model->user_agent . '</strong>',
			'<a href="' . $network_site_url . '">' . $network_site_url . '</a>',
		);

		return compact( 'subject', 'text' );
	}

	/**
	 * Gets email data for 404 lockouts.
	 *
	 * @param  Lockout_Log $model  The lockout log model.
	 * @param  string      $network_site_url  The network site URL.
	 *
	 * @return array Email subject and body text.
	 */
	private function get_404_lockout_email_data( Lockout_Log $model, string $network_site_url ): array {
		/* translators: %s: Site URL. */
		$subject  = sprintf( esc_html__( '404 lockout alert for %s', 'defender-security' ), $network_site_url );
		$settings = wd_di()->get( Notfound_Lockout::class );
		/* translators: 1: IP address, 2: Site URL, 3: Total attempt from an IP, 4: Tried, 5. Translation string. */
		$text = __(
			'The host %1$s has been locked out of %2$s due to more than %3$s 404 requests for the file %4$s. %5$s',
			'defender-security'
		);
		$text = sprintf(
			$text,
			'<strong>' . $model->ip . '</strong>',
			'<a href="' . $network_site_url . '">' . $network_site_url . '</a>',
			'<strong>' . $settings->attempt . '</strong>',
			'<strong>' . $model->tried . '</strong>',
			$this->get_lockout_duration_text( $settings->lockout_type, $settings->duration . ' ' . $settings->duration_unit )
		);

		return compact( 'subject', 'text' );
	}

	/**
	 * Gets the lockout duration text used in notification emails.
	 *
	 * @param  string $lockout_type  The lockout type.
	 * @param  string $duration  The lockout duration.
	 *
	 * @return string The lockout duration text.
	 */
	private function get_lockout_duration_text( string $lockout_type, string $duration ): string {
		if ( 'permanent' === $lockout_type ) {
			return esc_html__( 'Accordingly, the host has been permanently banned.', 'defender-security' );
		}

		return sprintf(
			/* translators: %s: Duration. */
			esc_html__( 'They have been locked out for %s.', 'defender-security' ),
			'<strong>' . esc_html( $duration ) . '</strong>'
		);
	}

	/**
	 * Renders the complete email content.
	 *
	 * @param  string $name  The recipient's name.
	 * @param  string $text  The email body text.
	 * @param  string $email  The recipient's email address.
	 * @param  object $service  The notification service object.
	 *
	 * @return string The rendered email content.
	 */
	private function render_email_content( string $name, string $text, string $email, object $service ): string {
		$logs_url = network_admin_url( 'admin.php?page=wdf-ip-lockout&view=logs' );
		// Need for activated Mask Login feature.
		$logs_url = apply_filters( 'report_email_logs_link', $logs_url, $email );
		// We don't call the Firewall controller to avoid cyclic dependency. It's a workaround with the simplest controller.
		$controller       = wd_di()->get( Blocklist_Monitor::class );
		$content_body     = $controller->render_partial(
			'email/login-lockout',
			array(
				'name'     => $name,
				// It's escaped value.
				'text'     => $text,
				'logs_url' => $logs_url,
			),
			false
		);
		$unsubscribe_link = $service->create_unsubscribe_url( $this->slug, $email );

		return $controller->render_partial(
			'email/index',
			array(
				'title'            => esc_html__( 'Firewall', 'defender-security' ),
				'content_body'     => $content_body,
				'unsubscribe_link' => $unsubscribe_link,
			),
			false
		);
	}

	/**
	 * Define labels.
	 *
	 * @return array The array of settings labels.
	 */
	public function labels(): array {
		return array(
			'notification'               => esc_html__( 'Firewall - Alert', 'defender-security' ),
			'login_lockout_notification' => esc_html__( 'Login Protection Lockout', 'defender-security' ),
			'ip_lockout_notification'    => esc_html__( '404 Detection Lockout', 'defender-security' ),
			'ua_lockout_notification'    => esc_html__( 'User Agent Lockout', 'defender-security' ),
			'notification_subscribers'   => esc_html__( 'Recipients', 'defender-security' ),
			'cooldown_enabled'           => esc_html__( 'Limit email alerts for repeat lockouts', 'defender-security' ),
			'cooldown_number_lockout'    => esc_html__( 'Repeat Lockouts Threshold', 'defender-security' ),
			'cooldown_period'            => esc_html__( 'Repeat Lockouts Period', 'defender-security' ),
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
	public function type_casting( array $configs ): array {
		if ( ! isset( $configs['threshold'] ) ) {
			$configs['threshold'] = $this->configs['threshold'] ?? 3;
		}
		if ( ! isset( $configs['cool_off'] ) ) {
			$configs['cool_off'] = $this->configs['cool_off'] ?? 24;
		}

		return $configs;
	}

	/**
	 * Returns lockout notification flags for the Hub.
	 *
	 * @return array
	 */
	public function get_hub_data(): array {
		if ( self::STATUS_ACTIVE !== $this->status ) {
			return array(
				'login_lockout' => false,
				'404_lockout'   => false,
				'ua_lockout'    => false,
			);
		}

		return array(
			'login_lockout' => wd_di()->get( Login_Lockout::class )->enabled,
			'404_lockout'   => wd_di()->get( Notfound_Lockout::class )->enabled,
			'ua_lockout'    => wd_di()->get( User_Agent_Lockout::class )->enabled,
		);
	}

	/**
	 * Normalizes firewall notification data after loading.
	 */
	protected function after_load(): void {
		parent::after_load();
		$this->title = esc_html__( 'Firewall alert', 'defender-security' );
	}
}
