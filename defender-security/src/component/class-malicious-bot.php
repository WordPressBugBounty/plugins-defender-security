<?php
/**
 * Handles malicious bot functionality.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Traits\Country;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Traits\File_Operations;
use WP_Defender\Integrations\Smartcrawl;
use WP_Defender\Model\Setting\User_Agent_Lockout;

/**
 * Handles operations to insert a weekly rotating hash URL into the footer,
 * and blocking IP addresses that access this URL.
 */
class Malicious_Bot extends Component {
	use Country;
	use File_Operations;

	public const URL_HASH_KEY           = 'wpdef_malicious_bot_url_hash';
	public const SCENARIO_MALICIOUS_BOT = 'malicious_bot';
	public const USER_AGENT_REGEX       = '/(^User-agent:\s*\*)/mi';

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
	private $start_comment = PHP_EOL . '# WP Defender - Begin' . PHP_EOL;

	/**
	 * The end comment for the robots.txt.
	 *
	 * @var string
	 */
	private $end_comment = PHP_EOL . '# WP Defender - End' . PHP_EOL;

	/**
	 * The model for handling the data.
	 *
	 * @var User_Agent_Lockout
	 */
	protected $model;

	/**
	 * SmartCrawl integration instance.
	 *
	 * @var Smartcrawl
	 */
	private $smartcrawl;

	/**
	 * Constructor for the Malicious_Bot class.
	 * Initializes the model and sets the path to the robots.txt file.
	 *
	 * @param User_Agent_Lockout $model The model instance for malicious bot functionality.
	 */
	public function __construct( User_Agent_Lockout $model ) {
		$this->model       = $model;
		$this->robots_file = ABSPATH . 'robots.txt';
		$this->smartcrawl  = new Smartcrawl();
	}

	/**
	 * Check if the malicious bot is enabled.
	 */
	public function is_enabled(): bool {
		return $this->model->enabled && $this->model->malicious_bot_enabled;
	}

	/**
	 * Get the hash for the malicious bot URL.
	 *
	 * @return string|false The hash if set, false otherwise.
	 */
	public function get_hash() {
		return get_site_option( self::URL_HASH_KEY, false );
	}

	/**
	 * Set the hash for the malicious bot URL.
	 *
	 * @param string $hash The hash to set, should be a 16-character hexadecimal string.
	 */
	private function set_hash( string $hash ) {
		update_site_option( self::URL_HASH_KEY, $hash );
	}

	/**
	 * Rotate the hash for the malicious bot URL.
	 */
	public function rotate_hash() {
		$new_hash = $this->generate_hash();
		$this->set_hash( $new_hash );

		flush_rewrite_rules();

		$this->remove_rule();
		$this->inject_rule();
	}

	/**
	 * Generate a new hash for the malicious bot URL.
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
			if ( $this->smartcrawl->should_serve_robots() ) {
				add_filter( 'smartcrawl_robots_txt_content', array( $this, 'add_bot_trap_to_smartcrawl_robots' ) );
			} else {
				$this->inject_rule();
			}
		} else {
			if ( $this->smartcrawl->is_activated() ) {
				remove_filter( 'smartcrawl_robots_txt_content', array( $this, 'add_bot_trap_to_smartcrawl_robots' ) );
			}
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
	public function get_block( string $eol = PHP_EOL ): string {
		$disallow_path = $this->get_hash();

		return $this->start_comment .
			'User-agent: *' . $eol .
			"Disallow: /{$disallow_path}" .
			$this->end_comment;
	}

	/**
	 * Inject the malicious bot rule into the robots.txt.
	 */
	public function inject_rule() {
		$wp_filesystem = $this->get_wp_filesystem();

		if ( $wp_filesystem->exists( $this->robots_file ) ) {
			// Inject rule into physical robots.txt file.
			$contents = $wp_filesystem->get_contents( $this->robots_file );
			if ( ! str_contains( $contents, $this->start_comment ) ) {
				$contents = $this->add_rules_to_content( $contents );

				$dir_name = pathinfo( $this->robots_file, PATHINFO_DIRNAME );
				if ( $wp_filesystem->is_writable( $dir_name ) ) {
					$wp_filesystem->put_contents( $this->robots_file, $contents );
				}
			}
		} else {
			// Inject virtual rule via filter.
			add_filter( 'robots_txt', array( $this, 'add_rules_to_content' ) );
		}
	}

	/**
	 * Add bot trap rules to SmartCrawl's robots.txt content.
	 *
	 * @param string $content The existing robots.txt content from SmartCrawl.
	 * @return string The modified robots.txt content with bot trap rules.
	 */
	public function add_bot_trap_to_smartcrawl_robots( $content ): string {
		if ( ! $this->is_enabled() ) {
			return $content;
		}

		return $this->add_rules_to_content( $content );
	}

	/**
	 * Remove the bot trap rule from the robots.txt.
	 */
	public function remove_rule() {
		$wp_filesystem = $this->get_wp_filesystem();

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

		if ( isset( $ip_to_country['iso'] ) ) {
			$model->country_iso_code = $ip_to_country['iso'];
		}

		switch ( $scenario ) {
			case self::SCENARIO_MALICIOUS_BOT:
			default:
				$model->type = Lockout_Log::LOCKOUT_MALICIOUS_BOT;
				$model->log  = esc_html__( 'Lockout occurred: Bot ignored robots.txt rules.', 'defender-security' );
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

	/**
	 * Merge the rule into existing User-agent: * block if present,
	 * otherwise prepends a new block.
	 *
	 * @param string $contents The existing robots.txt content.
	 *
	 * @return string The modified robots.txt content with Defender rule added.
	 */
	public function add_rules_to_content( string $contents ): string {
		if ( preg_match( self::USER_AGENT_REGEX, $contents ) ) {
			$disallow_path = $this->get_hash();
			$defender_rule = "{$this->start_comment}Disallow: /$disallow_path{$this->end_comment}";
			return preg_replace(
				self::USER_AGENT_REGEX,
				'$1' . PHP_EOL . $defender_rule,
				$contents,
				1
			);

		}
		return $this->get_block( PHP_EOL ) . $contents;
	}

	/**
	 * Detect if there's an empty Disallow line in robots.txt.
	 *
	 * @return bool True if empty Disallow line is detected, false otherwise.
	 */
	public function has_empty_disallow_line(): bool {
		$contents      = '';
		$wp_filesystem = $this->get_wp_filesystem();

		// Check physical robots.txt file first.
		if ( $wp_filesystem->exists( $this->robots_file ) ) {
			$contents = $wp_filesystem->get_contents( $this->robots_file );
		} elseif ( $this->smartcrawl->should_serve_robots() ) {
			// Get SmartCrawl virtual robots.txt content.
			$contents = $this->smartcrawl->get_robots_content();
		} else {
			// Get WordPress virtual robots.txt content.
			$contents = apply_filters( 'robots_txt', '', false );
		}

		if ( ! is_string( $contents ) || '' === trim( $contents ) ) {
			return false;
		}

		// Pattern to match "Disallow:" followed by optional whitespace and end of line (empty value).
		// Allows for optional leading whitespace before "Disallow:".
		$pattern = '/^\s*Disallow:\s*$/mi';
		if ( ! preg_match( $pattern, $contents ) ) {
			return false;
		}

		// Make sure it's not within our managed block.
		$defender_block_pattern    = '/' . preg_quote( $this->start_comment, '/' ) .
			'.*?' . preg_quote( $this->end_comment, '/' ) . '/s';
		$contents_without_defender = preg_replace( $defender_block_pattern, '', $contents );

		return preg_match( $pattern, $contents_without_defender ) === 1;
	}
}
