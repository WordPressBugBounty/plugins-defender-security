<?php
/**
 * Handles the security key and salt generation for WordPress configuration.
 *
 * @package WP_Defender\Component\Security_Tweaks
 */

namespace WP_Defender\Component\Security_Tweaks;

use WP_Error;
use Exception;
use Throwable;
use Calotes\Base\Component;
use Calotes\Component\Response;
use WP_Defender\Model\Setting\Mask_Login;
use WP_Defender\Model\Setting\Security_Tweaks;
use WP_Defender\Traits\Security_Tweaks_Option;

/**
 * Class Security_Key
 */
class Security_Key extends Component implements Security_Key_Const_Interface {

	use Security_Tweaks_Option;

	/**
	 * The slug identifier for the component.
	 *
	 * @var string
	 */
	public $slug = 'security-key';
	/**
	 * Default reminder duration for regenerating security keys.
	 *
	 * @var string
	 */
	public $default_days = '60 days';
	/**
	 * Duration after which a reminder for regeneration is triggered.
	 *
	 * @var null
	 */
	public $reminder_duration = null;
	/**
	 * Date of the last reminder.
	 *
	 * @var null
	 */
	public $reminder_date = null;
	/**
	 * Timestamp of the last modification of security keys.
	 *
	 * @var null
	 */
	public $last_modified = null;
	/**
	 * Path to the wp-config.php file.
	 *
	 * @var string
	 */
	public $file;

	/**
	 * Flag to automate the security key/salt generation.
	 *
	 * @var bool
	 */
	private $is_autogenerate_keys = true;

	/**
	 * Constructor for Security_Key.
	 */
	public function __construct() {
		$this->file = defender_wp_config_path();
		$this->add_hooks();
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

			return $reminder_date > time();
		}
	}

	/**
	 * Get options.
	 *
	 * @return void
	 */
	private function get_options(): void {
		$options                 = get_site_option( 'defender_security_tweaks_' . $this->slug );
		$this->reminder_date     = ! empty( $options['reminder_date'] ) ? $options['reminder_date'] : null;
		$this->reminder_duration = ! empty( $options['reminder_duration'] ) ? $options['reminder_duration'] : $this->default_days;

		$last_modified = $this->get_wp_config_last_modified_time();
		if ( false === $last_modified ) {
			$last_modified = $options['last_modified'] ?? null;
		} elseif ( ! empty( $options['last_modified'] ) && $options['last_modified'] < $last_modified ) {
			$last_modified = $options['last_modified'];
		}
		$this->last_modified = $last_modified;

		$this->is_autogenerate_keys = ! empty( $options['is_autogenerate_keys'] )
			? (bool) $options['is_autogenerate_keys']
			: true;
	}

	/**
	 * Here is the code for processing. If the return is true or Response, we add it to resolve list. WP_Error if any error.
	 *
	 * @return bool|WP_Error|Response
	 */
	public function process() {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}
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

		$contents  = $wp_filesystem->get_contents( $this->file );
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

		if ( ! empty( $new_salts ) ) {
			$new_salts = PHP_EOL .
						'/* DEFENDER GENERATED SALTS */' .
						PHP_EOL .
						$new_salts .
						PHP_EOL;

			$contents = $this->append_salts( $contents, $new_salts );
		}

		$is_done = (bool) file_put_contents( $this->file, $contents, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents

		if ( $is_done ) {
			$values                  = get_site_option( 'defender_security_tweaks_' . $this->slug, array() );
			$this->last_modified     = time();
			$values['last_modified'] = time();
			update_site_option( 'defender_security_tweaks_' . $this->slug, $values );

			$url        = wp_login_url( network_admin_url( 'admin.php?page=wdf-hardener' ) );
			$mask_login = new Mask_Login();

			if ( $mask_login->is_active() ) {
				$url = $mask_login->get_new_login_url();
			}

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
	private function get_salts() {
		$response = wp_safe_remote_get( 'https://api.wordpress.org/secret-key/1.1/salt/' );

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'defender_salts_not_found',
				esc_html__( 'Unable to generate salts. Please try again.', 'defender-security' )
			);
		}

		return array_filter( explode( "\n", wp_remote_retrieve_body( $response ) ) );
	}

	/**
	 * Get how long the wp-config file is last updated.
	 *
	 * @return int|string
	 */
	private function get_last_modified_days() {
		$current_time = time();
		$days_ago     = ( $current_time - $this->last_modified ) / DAY_IN_SECONDS;
		$days_ago     = $days_ago ? round( $days_ago ) : 'unknown';

		return $days_ago ?? 1;
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
	 * Return a summary data of this tweak.
	 *
	 * @return array
	 */
	public function to_array(): array {
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

		return array(
			'slug'             => $this->slug,
			'title'            => esc_html__( 'Update old security keys', 'defender-security' ),
			'errorReason'      => $error_message,
			'successReason'    => sprintf(
			/* translators: %s: number of days */
				esc_html__( 'Your security keys are less than %s days old, nice work.', 'defender-security' ),
				$get_last_modified_days
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

		$this->is_autogenerate_keys = is_null( $is_autogenerate_keys )
			? true
			: (bool) $is_autogenerate_keys;

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
		$this->is_autogenerate_keys = (bool) $value;

		return $this->update_option(
			'is_autogenerate_keys',
			$this->is_autogenerate_keys
		);
	}

	/**
	 * Method to initialize component hooks.
	 *
	 * @return void
	 */
	public function add_hooks(): void {
		add_action( 'wpdef_sec_key_gen', array( &$this, 'cron_process' ) );
	}

	/**
	 * Cron schedule.
	 *
	 * @return void
	 */
	public function cron_schedule(): void {
		if (
			true === $this->get_is_autogenerate_keys() &&
			! wp_next_scheduled( 'wpdef_sec_key_gen' )
		) {
			$display_name = $this->get_option( 'reminder_duration' );

			if ( empty( $display_name ) ) {
				$display_name = $this->default_days;
			}

			$schedule_detail = $this->get_schedule_detail( $display_name );

			$schedule_key      = key( $schedule_detail );
			$schedule_interval = time() + $schedule_detail[ $schedule_key ]['interval'];

			wp_schedule_event(
				$schedule_interval,
				$schedule_key,
				'wpdef_sec_key_gen'
			);
		}
	}

	/**
	 * Cron unscheduled.
	 *
	 * @return void
	 */
	public function cron_unschedule(): void {
		$timestamp = wp_next_scheduled( 'wpdef_sec_key_gen' );

		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'wpdef_sec_key_gen' );
		}
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
				$this->process();
			}
		} catch ( Throwable $th ) {
			// PHP 7+ catch.
			$this->log( get_class( $th ) . ': ' . $th->getMessage(), 'internal.log' );
		} catch ( Exception $e ) {
			$this->log( get_class( $e ) . ': ' . $e->getMessage(), 'internal.log' );
		}
	}

	/**
	 * Get scheduler detail.
	 *
	 * @param  string $display_name  The name to filter the schedules list.
	 *
	 * @return array Return filtered schedule detail.
	 */
	private function get_schedule_detail( $display_name ) {
		$all_schedules = wp_get_schedules();

		$schedule_detail = array_filter(
			$all_schedules,
			function ( $arr ) use ( $display_name ) {
				return $display_name === $arr['display'];
			}
		);

		return $schedule_detail;
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
	 * @param  string|false $contents  Text content of wp-config.php.
	 * @param  string       $new_salts  Salts need to be appended.
	 *
	 * @return string Text content after salts appended.
	 */
	private function append_salts( $contents, string $new_salts ): string {
		$config_array = preg_split( '/\R/', $contents );

		$line_no = $this->search_line( // Important $line_no is array index therefore 0 means first line.
			$config_array,
			"That's all, stop editing!" // Warning text in wp-config file.
		);

		if ( false === $line_no ) { // If faster prediction failed.
			// Regex prediction (slow one but last resort). Matches multiline of: "if ( ! defined( 'ABSPATH' ) ) {".
			$regex = "/^\s*if\s*\(\s*\!\s*defined\s*\(\s*['|\"]ABSPATH['|\"]\s*\)\s*\)\s*\{?\s*/m";

			$line_no = $this->grep_line( $config_array, $regex );
		}

		// Splice before WP initialize and append.
		array_splice( $config_array, $line_no, 0, $new_salts );

		return implode( PHP_EOL, $config_array );
	}

	/**
	 * Simple array search and return the array index of first match value.
	 *
	 * @param  array  $haystack  Array of text for search.
	 * @param  string $search_text  Search term.
	 *
	 * @return int|bool On found return array index else false.
	 */
	private function search_line( $haystack, string $search_text ) {
		$filtered_array = array_filter(
			$haystack,
			function ( $el ) use ( $search_text ) {
				return ( false !== strpos( $el, $search_text ) );
			}
		);

		if ( empty( $filtered_array ) ) {
			return false;
		}

		reset( $filtered_array );

		return key( $filtered_array );
	}

	/**
	 * Grep array search and return the array index of first match value.
	 *
	 * @param  array  $haystack  Array of text for search.
	 * @param  string $regex  Search term (accepts regex).
	 *
	 * @return int|bool On found return array index else false.
	 */
	private function grep_line( $haystack, string $regex ) {
		$filtered_array = preg_grep( $regex, $haystack );

		if ( empty( $filtered_array ) ) {
			return false;
		}
		reset( $filtered_array );

		return key( $filtered_array );
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
	private function get_wp_config_last_modified_time() {
		$file = $this->file;
		if ( ! file_exists( $file ) ) {
			$file = ABSPATH . WPINC . '/general-template.php';
		}

		return filemtime( $file );
	}
}
