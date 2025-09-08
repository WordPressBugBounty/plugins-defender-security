<?php
/**
 * Handles bot trap functionality.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Model\Setting\User_Agent_Lockout;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Traits\Country;

/**
 * Handles operations to insert a weekly rotating hash URL into the footer,
 * and blocking IP addresses that access this URL.
 */
class Bot_Trap extends Component {
	use Country;

	public const URL_HASH_KEY      = 'wpdef_bot_trap_url_hash';
	public const SCENARIO_BOT_TRAP = 'bot_trap';

	/**
	 * The path to the robots.txt file.
	 *
	 * @var string
	 */
	private $robots_file;

	/**
	 * The start comment for the robots.txt.
	 *
	 * @var string
	 */
	private $start_comment = '# WP Defender - Begin';

	/**
	 * The end comment for the robots.txt.
	 *
	 * @var string
	 */
	private $end_comment = '# WP Defender - End';

	/**
	 * The model for handling the data.
	 *
	 * @var User_Agent_Lockout
	 */
	protected $model;

	/**
	 * Constructor for the Bot_Trap class.
	 * Initializes the model and sets the path to the robots.txt file.
	 *
	 * @param User_Agent_Lockout $model The model instance for bot trap functionality.
	 */
	public function __construct( User_Agent_Lockout $model ) {
		$this->model       = $model;
		$this->robots_file = ABSPATH . 'robots.txt';
	}

	/**
	 * Check if the bot trap is enabled.
	 */
	public function is_enabled(): bool {
		return $this->model->enabled && $this->model->bot_trap_enabled;
	}

	/**
	 * Get the hash for the bot trap URL.
	 *
	 * @return string|false The hash if set, false otherwise.
	 */
	public function get_hash() {
		return get_site_option( self::URL_HASH_KEY, false );
	}

	/**
	 * Set the hash for the bot trap URL.
	 *
	 * @param string $hash The hash to set, should be a 16-character hexadecimal string.
	 */
	private function set_hash( string $hash ) {
		update_site_option( self::URL_HASH_KEY, $hash );
	}

	/**
	 * Rotate the hash for the bot trap URL.
	 */
	public function rotate_hash() {
		$new_hash = $this->generate_hash();
		$this->set_hash( $new_hash );

		flush_rewrite_rules();

		$this->remove_rule();
		$this->inject_rule();
	}

	/**
	 * Generate a new hash for the bot trap URL.
	 *
	 * @return string|false A 16-character hexadecimal string or false on failure.
	 */
	private function generate_hash() {
		return substr( bin2hex( Crypt::random_bytes( 32 ) ), 0, 16 );
	}

	/**
	 * Handle the robots.txt rule.
	 */
	public function handle_robots_txt() {
		if ( $this->is_enabled() ) {
			$this->inject_rule();
		} else {
			$this->remove_rule();
		}
	}

	/**
	 * Get rule block for robots.txt.
	 *
	 * @param string $eol The end-of-line character to use, defaults to "\n".
	 *
	 * @return string The block of text to be added to the robots.txt file.
	 */
	public function get_block( string $eol = "\n" ): string {
		$disallow_path = $this->get_hash();

		return $this->start_comment . $eol .
			'User-agent: *' . $eol .
			"Disallow: /{$disallow_path}" . $eol .
			$this->end_comment;
	}

	/**
	 * Inject the bot trap rule into the robots.txt.
	 */
	public function inject_rule() {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		if ( $wp_filesystem->exists( $this->robots_file ) ) {
			// Inject rule into physical robots.txt file.
			$contents = $wp_filesystem->get_contents( $this->robots_file );
			$eol      = $this->detect_line_ending( $contents );

			if ( strpos( $contents, $this->start_comment ) === false ) {
				$block     = $eol . $this->get_block( $eol ) . $eol;
				$contents .= $block;

				$dir_name = pathinfo( $this->robots_file, PATHINFO_DIRNAME );
				if ( $wp_filesystem->is_writable( $dir_name ) ) {
					$wp_filesystem->put_contents( $this->robots_file, $contents );
				}
			}
		} else {
			// Inject virtual rule via filter.
			add_filter(
				'robots_txt',
				function ( $output ) {
					return $output . "\n" . $this->get_block();
				},
				10,
				2
			);
		}
	}

	/**
	 * Remove the bot trap rule from the robots.txt.
	 */
	public function remove_rule() {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		if ( ! $wp_filesystem->exists( $this->robots_file ) ) {
			return;
		}

		$contents = $wp_filesystem->get_contents( $this->robots_file );
		$eol      = $this->detect_line_ending( $contents );

		// Remove only the plugin block.
		$pattern = '/\\s*' . preg_quote( $this->start_comment, '/' ) .
		'.*?' . preg_quote( $this->end_comment, '/' ) . '\\s*/s';

		$new_contents = preg_replace( $pattern, '', $contents );
		$new_contents = trim( $new_contents );

		if ( '' === $new_contents ) {
			// File only had plugin block — delete it.
			wp_delete_file( $this->robots_file );
		} else {
			$dir_name = pathinfo( $this->robots_file, PATHINFO_DIRNAME );
			if ( $wp_filesystem->is_writable( $dir_name ) ) {
				$wp_filesystem->put_contents( $this->robots_file, $new_contents . $eol );
			}
		}
	}

	/**
	 * Log the event into db, we will use the data in logs page later.
	 *
	 * @param  string $ip  The IP address involved in the event.
	 * @param  string $uri  The URI that was accessed.
	 * @param  string $scenario  The scenario under which the event is logged.
	 */
	public function log_event( $ip, $uri, $scenario ) {
		$model             = new Lockout_Log();
		$model->ip         = $ip;
		$user_agent        = defender_get_data_from_request( 'HTTP_USER_AGENT', 's' );
		$model->user_agent = isset( $user_agent ) ? User_Agent::fast_cleaning( $user_agent ) : null;
		$model->date       = time();
		$model->tried      = $uri;
		$model->blog_id    = get_current_blog_id();

		$ip_to_country = $this->ip_to_country( $ip );

		if ( ! empty( $ip_to_country ) && isset( $ip_to_country['iso'] ) ) {
			$model->country_iso_code = $ip_to_country['iso'];
		}

		switch ( $scenario ) {
			case self::SCENARIO_BOT_TRAP:
			default:
				$model->type = Lockout_Log::LOCKOUT_BOT_TRAP;
				$model->log  = esc_html__( 'Locked out by Bot Trap', 'defender-security' );
				break;
		}
		$model->save();
	}

	/**
	 * Creates a lockout for a blocked IP.
	 *
	 * @param  Lockout_Ip $model    The lockout IP model.
	 * @param  string     $message  The lockout message.
	 * @param  int        $time     The timestamp when the lockout will be lifted.
	 */
	public function create_blocked_lockout( &$model, $message, $time ) {
		$model->lockout_message = $message;
		$model->release_time    = $time;
		$model->save();
	}
}
