<?php
/**
 * Handles the security key and salt generation for WordPress configuration.
 *
 * @package WP_Defender\Component\Security_Tweaks
 */

namespace WP_Defender\Component\Security_Tweaks;

use WP_Error;
use Throwable;
use Calotes\Component\Response;
use WP_Defender\Traits\File_Operations;
use WP_Defender\Model\Setting\Mask_Login;
use WP_Defender\Model\Setting\Security_Tweaks;
use WP_Defender\Traits\Security_Tweaks_Option;
use WP_Defender\Component\Network_Cron_Manager;
use WP_Defender\Component\Security_Tweak;

/**
 * Class Security_Key
 */
class Security_Key extends Abstract_Security_Tweaks implements Security_Key_Const_Interface {

	use File_Operations;
	use Security_Tweaks_Option;

	public const REGENERATE_SALT_NEXT_RUN_OPTION = 'wpdef_regereate_salt_next_run';

	/**
	 * The slug identifier for the component.
	 *
	 * @var string
	 */
	public string $slug = 'security-key';
	/**
	 * Default reminder duration for regenerating security keys.
	 *
	 * @var string
	 */
	public string $default_days = '60 days';
	/**
	 * Duration after which a reminder for regeneration is triggered.
	 *
	 * @var string
	 */
	public string $reminder_duration = '60 days';
	/**
	 * Date of the last reminder.
	 *
	 * @var int
	 */
	public int $reminder_date = 0;
	/**
	 * Timestamp of the last modification of security keys.
	 *
	 * @var int
	 */
	public int $last_modified = 0;
	/**
	 * Path to the wp-config.php file.
	 *
	 * @var string
	 */
	public string $file;

	/**
	 * Flag to automate the security key/salt generation.
	 *
	 * @var bool
	 */
	private bool $is_autogenerate_keys = true;

	/**
	 * Constructor for Security_Key.
	 */
	public function __construct() {
		$this->file = defender_wp_config_path();
		$this->get_options();
		$this->cron_schedule();
	}

	/**
	 * Check whether the issue has been resolved or not.
	 *
	 * @return bool|void
	 */
	public function check() {
		if ( ! $this->is_salts_exist() ) {
			return false;
		}

		if ( $this->last_modified ) {
			$reminder_date = strtotime( '+' . $this->reminder_duration, $this->last_modified );

			return $reminder_date > defender_get_current_time();
		}
	}

	/**
	 * Get options.
	 *
	 * @return void
	 */
	private function get_options(): void {
		$options                 = get_site_option( 'defender_security_tweaks_' . $this->slug );
		$this->reminder_date     = $options['reminder_date'] ?? 0;
		$this->reminder_duration = isset( $options['reminder_duration'] ) && '' !== $options['reminder_duration'] ? $options['reminder_duration'] : $this->default_days;

		$last_modified = $this->get_wp_config_last_modified_time();
		if ( false === $last_modified ) {
			$last_modified = $options['last_modified'] ?? null;
		} elseif ( isset( $options['last_modified'] ) && is_int( $options['last_modified'] ) && 0 < $options['last_modified'] && $options['last_modified'] < $last_modified ) {
			$last_modified = $options['last_modified'];
		}
		$this->last_modified = $last_modified;

		$this->is_autogenerate_keys = isset( $options['is_autogenerate_keys'] );
	}

	/**
	 * Here is the code for processing. If the return is true or Response, we add it to resolve list. WP_Error if any error.
	 *
	 * @return bool|WP_Error|Response
	 */
	public function process() {
		$is_done = $this->update_keys();

		if ( is_wp_error( $is_done ) ) {
			return $is_done;
		}

		if ( $is_done ) {
			$mask_login = wd_di()->get( Mask_Login::class );
			$url        = $mask_login->is_active()
				? $mask_login->get_new_login_url()
				: wp_login_url( network_admin_url( 'admin.php?page=wdf-hardener' ) );

			$interval = 3;

			return new Response(
				true,
				array(
					'message'  => sprintf(
						/* translators: 1: login link, 2: line break, 3: timer. */
						esc_html__(
							'All key salts have been regenerated. You will now need to %1$s. %2$s This will auto reload after %3$s seconds.',
							'defender-security'
						),
						'<a href="' . $url . '"><strong>' . esc_html__( 're-login', 'defender-security' ) . '</strong></a>',
						'<br>',
						'<span class="hardener-timer">' . $interval . '</span>'
					),
					'redirect' => $url,
					'interval' => $interval,
				)
			);
		}

		return $is_done;
	}

	/**
	 * This is for un-do stuff that has be done in @process.
	 *
	 * @return bool
	 */
	public function revert(): bool {
		return true;
	}

	/**
	 * Shield up.
	 *
	 * @return bool
	 */
	public function shield_up(): bool {
		return true;
	}

	/**
	 * Get salts to be placed in wp-config.php.
	 *
	 * @return array|WP_Error
	 */
	private function get_salts(): WP_Error|array {
		$response = wp_safe_remote_get( 'https://api.wordpress.org/secret-key/1.1/salt/' );

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'defender_salts_not_found',
				esc_html__( 'Unable to generate salts. Please try again.', 'defender-security' )
			);
		}

		$raw_salts = explode( "\n", wp_remote_retrieve_body( $response ) );
		$salts     = array();

		foreach ( $raw_salts as $salt ) {
			$salt = trim( $salt );
			if ( '' === $salt ) {
				continue;
			}
			$salts[] = stripslashes( $salt );
		}

		return $salts;
	}

	/**
	 * Get how long the wp-config file is last updated.
	 *
	 * @return int|string
	 */
	private function get_last_modified_days(): int|string {
		$current_time = defender_get_current_time();
		$days_ago     = ( $current_time - $this->last_modified ) / DAY_IN_SECONDS;
		return $days_ago ? (int) round( $days_ago ) : 'unknown';
	}

	/**
	 * Get all the constants.
	 *
	 * @return array
	 */
	private function get_constants(): array {
		return array(
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		);
	}

	/**
	 * Retrieve the tweak's label.
	 *
	 * @return string
	 */
	public function get_label(): string {
		return esc_html__( 'Update old security keys', 'defender-security' );
	}

	/**
	 * Get the error reason.
	 *
	 * @return string
	 */
	public function get_error_reason(): string {
		$get_last_modified_days = $this->get_last_modified_days();

		if ( 'unknown' === $get_last_modified_days ) {
			$error_message = esc_html__(
				'We can\'t tell how old your security keys are, perhaps it\'s time to update them?',
				'defender-security'
			);
		}
		if ( ! $this->is_salts_exist() ) {
			$error_message = esc_html__(
				'One or more security salts aren\'t defined in wp-config.php. Time to regenerate them!',
				'defender-security'
			);
		} else {
			$error_message = sprintf(
			/* translators: %s: number of days */
				esc_html__( 'Your current security keys are %s days old. Time to update them!', 'defender-security' ),
				$get_last_modified_days
			);
		}

		return $error_message;
	}

	/**
	 * Return a summary data of this tweak.
	 *
	 * @return array
	 */
	public function to_array(): array {
		return array(
			'slug'             => $this->slug,
			'title'            => $this->get_label(),
			'errorReason'      => $this->get_error_reason(),
			'successReason'    => sprintf(
			/* translators: %s: number of days */
				esc_html__( 'Your security keys are less than %s days old, nice work.', 'defender-security' ),
				$this->get_last_modified_days()
			),
			'misc'             => array(
				'reminder' => $this->reminder_duration,
			),
			'bulk_description' => esc_html__(
				'Your current security keys are unknown days old. Time to update them! We will update the frequency to 60 days.',
				'defender-security'
			),
			'bulk_title'       => esc_html__( 'Security Keys', 'defender-security' ),
		);
	}

	/**
	 * Getter method of is_autogenerate_keys.
	 *
	 * @return bool. Return true or false which is used to trigger auto generation of security salt/key.
	 */
	public function get_is_autogenerate_keys(): bool {
		$is_autogenerate_keys = $this->get_option( 'is_autogenerate_keys' );

		$this->is_autogenerate_keys = is_null( $is_autogenerate_keys ) || (bool) $is_autogenerate_keys;

		return $this->is_autogenerate_keys;
	}

	/**
	 * Setter method of is_autogenerate_keys.
	 *
	 * @param  bool $value  Boolean flag of the is_autogenerate_keys.
	 *
	 * @return bool Return true if value updated, otherwise false.
	 */
	public function set_is_autogenrate_keys( bool $value ): bool {
		$this->is_autogenerate_keys = $value;

		return $this->update_option(
			'is_autogenerate_keys',
			$this->is_autogenerate_keys
		);
	}

	/**
	 * Cron schedule.
	 *
	 * @return void
	 */
	public function cron_schedule(): void {
		if (
			true === $this->get_is_autogenerate_keys()
		) {
			$display_name = $this->get_option( 'reminder_duration' );

			if ( ! is_string( $display_name ) || '' === $display_name ) {
				$display_name = $this->default_days;
			}

			/**
			 * Network Cron Manager instance.
			 *
			 * @var Network_Cron_Manager $network_cron_manager
			 */
			$network_cron_manager = wd_di()->get( Network_Cron_Manager::class );

			$interval_seconds = strtotime( $display_name, 0 );
			$start_time       = defender_get_current_time() + $interval_seconds;

			$network_cron_manager->register_callback(
				'wpdef_sec_key_gen',
				array( $this, 'cron_process' ),
				$interval_seconds,
				$start_time,
			);

		}
	}

	/**
	 * Cron unscheduled.
	 *
	 * @return void
	 */
	public function cron_unschedule(): void {
		/**
		 * Network Cron Manager instance.
		 *
		 * @var Network_Cron_Manager $network_cron_manager
		 */
		$network_cron_manager = wd_di()->get( Network_Cron_Manager::class );
		$network_cron_manager->remove_callback( 'wpdef_sec_key_gen' );
	}

	/**
	 * Cron schedule security key/salt generation process.
	 *
	 * @return void
	 */
	public function cron_process(): void {
		try {
			$security_tweak_model = new Security_Tweaks();
			if ( ! $security_tweak_model->is_tweak_ignore( $this->slug ) &&
				true === $this->get_is_autogenerate_keys()
			) {
				$this->update_keys();
			}
		} catch ( Throwable $th ) {
			$this->log( 'Security Key. Cron Throwable: ' . get_class( $th ) . ': ' . $th->getMessage(), Security_Tweak::LOG_FILE_NAME );
		}
	}

	/**
	 * Check all salts are exists.
	 *
	 * @return bool Return true if all constants have salt else false.
	 */
	private function is_salts_exist(): bool {
		foreach ( $this->get_constants() as $constants ) {
			if ( ! defined( $constants ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Append salt to wp-config.php file content string.
	 *
	 * @param bool|string $contents  Text content of wp-config.php.
	 * @param  string      $new_salts  Salts need to be appended.
	 *
	 * @return string Text content after salts appended.
	 */
	private function append_salts( bool|string $contents, string $new_salts ): string {
		$pattern = '/(define\(\s*\'AUTH_KEY\'.*?\);)\s*' .
					'(define\(\s*\'SECURE_AUTH_KEY\'.*?\);)\s*' .
					'(define\(\s*\'LOGGED_IN_KEY\'.*?\);)\s*' .
					'(define\(\s*\'NONCE_KEY\'.*?\);)\s*' .
					'(define\(\s*\'AUTH_SALT\'.*?\);)\s*' .
					'(define\(\s*\'SECURE_AUTH_SALT\'.*?\);)\s*' .
					'(define\(\s*\'LOGGED_IN_SALT\'.*?\);)\s*' .
					'(define\(\s*\'NONCE_SALT\'.*?\);)/s';

		if ( preg_match( $pattern, $contents ) ) {
			return preg_replace( $pattern, $new_salts, $contents );
		} else {
			return preg_replace( '/(define\(\s*\'DB_NAME\'\s*,.*?\);)/s', $new_salts . PHP_EOL . '$1', $contents );
		}
	}

	/**
	 * Return collection of reminder frequencies.
	 *
	 * @return array
	 */
	public function reminder_frequencies(): array {
		return array(
			'30 days',
			'60 days',
			'90 days',
			'6 months',
			'1 year',
		);
	}

	/**
	 * Get the last modified time of wp-config file.
	 *
	 * @return int|false
	 * @since 3.10.0
	 */
	private function get_wp_config_last_modified_time(): bool|int {
		$file = $this->file;
		if ( ! file_exists( $file ) ) {
			$file = ABSPATH . WPINC . '/general-template.php';
		}

		return filemtime( $file );
	}

	/**
	 * Update keys.
	 *
	 * @return WP_Error|bool|array True if success. WP_Error if any error.
	 */
	private function update_keys(): WP_Error|bool|array {
		$wp_filesystem = $this->get_wp_filesystem();

		if ( ! $wp_filesystem->is_writable( $this->file ) ) {
			return new WP_Error(
				'defender_file_not_writable',
				/* translators: %s: file path */
				sprintf( esc_html__( 'The file %s is not writable', 'defender-security' ), $this->file )
			);
		}

		$constants = $this->get_constants();
		$salts     = $this->get_salts();

		if ( is_wp_error( $salts ) ) {
			return $salts;
		}

		$contents = $wp_filesystem->get_contents( $this->file );

		$new_salts = '';

		foreach ( $constants as $key => $const ) {
			if ( defined( $const ) ) {
				$pattern     = "/^define\(\s*['|\"]{$const}['|\"],(.*)\)\s*;/m";
				$replacement = $salts[ $key ];
				$contents    = preg_replace_callback(
					$pattern,
					function () use ( $replacement ) {
						return $replacement;
					},
					$contents
				);
			} else {
				$new_salts .= $salts[ $key ] . PHP_EOL;
			}
		}

		if ( '' !== $new_salts ) {
			$new_salts = PHP_EOL .
						'/* DEFENDER GENERATED SALTS */' .
						PHP_EOL .
						$new_salts .
						PHP_EOL;

			$contents = $this->append_salts( $contents, $new_salts );
		}

		$is_done = $wp_filesystem->put_contents( $this->file, $contents, FS_CHMOD_FILE );

		if ( ! $is_done ) {
			return false;
		}
		$values                  = get_site_option( 'defender_security_tweaks_' . $this->slug, array() );
		$this->last_modified     = defender_get_current_time();
		$values['last_modified'] = defender_get_current_time();
		update_site_option( 'defender_security_tweaks_' . $this->slug, $values );
		$this->log( 'Security keys are updated.', Security_Tweak::LOG_FILE_NAME );
		if ( is_multisite() && ! headers_sent() ) {
			// Delete cookies forced.
			wp_clear_auth_cookie();
		}

		return true;
	}
}
