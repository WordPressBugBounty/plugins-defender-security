<?php
/**
 * Handles CAPTCHA functionality.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Error;
use Calotes\Base\Component;
use WP_Defender\Integrations\Buddypress;
use WP_Defender\Integrations\Woocommerce;
use WP_Defender\Component\Captcha\Turnstile;
use WP_Defender\Component\Captcha\Recaptcha;
use WP_Defender\Component\Captcha\Interface_Provider;
use WP_Defender\Model\Setting\Captcha as Captcha_Model;

/**
 * Provides methods to handle CAPTCHA integration, including rendering, validation, and script management.
 */
class Captcha extends Component {

	/**
	 * Default form identifiers for CAPTCHA integration.
	 */
	public const DEFAULT_LOGIN_FORM = 'login', DEFAULT_REGISTER_FORM = 'register', DEFAULT_LOST_PASSWORD_FORM = 'lost_password', DEFAULT_COMMENT_FORM = 'comments';

	/**
	 * The CAPTCHA settings model.
	 *
	 * @var Captcha_Model
	 */
	protected Captcha_Model $model;

	/**
	 * WooCommerce integration instance.
	 *
	 * @var Woocommerce|null
	 */
	private ?Woocommerce $woo;
	/**
	 * BuddyPress integration instance.
	 *
	 * @var Buddypress|null
	 */
	private ?Buddypress $buddypress;
	/**
	 * Active CAPTCHA provider instance.
	 *
	 * @var Interface_Provider|null
	 */
	private ?Interface_Provider $provider = null;

	/**
	 * Captcha constructor.
	 *
	 * @param Captcha_Model $model The CAPTCHA settings model.
	 */
	public function __construct( Captcha_Model $model ) {
		$this->model      = $model;
		$this->woo        = wd_di()->get( Woocommerce::class );
		$this->buddypress = wd_di()->get( Buddypress::class );
		$this->provider   = $this->get_provider();
	}

	/**
	 * Get the active captcha provider.
	 *
	 * @return Interface_Provider
	 */
	public function get_provider(): Interface_Provider {
		if ( 'recaptcha' === $this->model->provider && ! $this->provider instanceof Recaptcha ) {
			$this->provider = new Recaptcha( $this->model );
		}
		if ( Captcha_Model::TURNSTILE === $this->model->provider && ! $this->provider instanceof Turnstile ) {
			$this->provider = new Turnstile( $this->model );
		}
		// Fallback to Recaptcha if provider is invalid.
		if ( null === $this->provider ) {
			$this->provider = new Recaptcha( $this->model );
		}
		return $this->provider;
	}

	/**
	 * Retrieves the list of default forms where CAPTCHA can be integrated.
	 *
	 * @return array An associative array of form identifiers and their display names.
	 */
	public static function get_forms(): array {
		return array(
			self::DEFAULT_LOGIN_FORM         => esc_html__( 'Login', 'defender-security' ),
			self::DEFAULT_REGISTER_FORM      => esc_html__( 'Register', 'defender-security' ),
			self::DEFAULT_LOST_PASSWORD_FORM => esc_html__( 'Lost Password', 'defender-security' ),
			self::DEFAULT_COMMENT_FORM       => esc_html__( 'Comments', 'defender-security' ),
		);
	}

	/**
	 * Determines if any CAPTCHA location is enabled.
	 *
	 * @param bool $exist_woo Whether WooCommerce is active.
	 * @param bool $exist_bp Whether BuddyPress is active.
	 *
	 * @return bool True if any location is enabled, false otherwise.
	 */
	public function enable_any_location( bool $exist_woo, bool $exist_bp ): bool {
		return $this->model->enable_default_location() || $this->model->check_woo_locations( $exist_woo ) || $this->model->check_buddypress_locations( $exist_bp );
	}

	/**
	 * Modifies the script loader tag for the 'wpdef_captcha_api' handle.
	 *
	 * @param string $tag The original script loader tag.
	 * @param string $handle The handle being loaded.
	 *
	 * @return string The modified script loader tag.
	 */
	public function script_loader_tag( string $tag, string $handle ): string {
		if ( 'wpdef_captcha_api' === $handle ) {
			$tag = str_replace( ' src', ' data-cfasync="false" async="async" defer="defer" src', $tag );
		}

		return $tag;
	}

	/**
	 * Add scripts when comments are lazy loaded.
	 *
	 * @return void
	 * @since 2.6.1
	 */
	public function add_scripts_for_lazy_load(): void {
		if ( in_array(
			$this->provider->type,
			array(
				'v2_checkbox',
				'v2_invisible',
			),
			true
		) && ( is_single() || is_page() ) && comments_open() ) {
			if ( ! wp_script_is( 'wpdef_captcha_api', 'registered' ) ) {
				$api_url = $this->provider->get_api_url();
				$deps    = array( 'jquery' );
				wp_register_script( 'wpdef_captcha_api', $api_url, $deps, DEFENDER_VERSION, true );
			}

			$this->add_captcha_scripts();
		}
	}

	/**
	 * Enqueues the necessary scripts for the reCAPTCHA frontend.
	 *
	 * @return void
	 */
	public function add_captcha_scripts(): void {
		if ( isset( $this->provider->type ) ) {
			$this->remove_duplicate_captcha_scripts();
		}
		$handle  = $this->provider->get_script_handle();
		$src_url = $this->provider->get_script_url();
		if ( ! wp_script_is( $handle ) ) {
			wp_enqueue_script(
				$handle,
				plugins_url( $src_url, WP_DEFENDER_FILE ),
				array(
					'jquery',
					'wpdef_captcha_api',
				),
				DEFENDER_VERSION,
				true
			);
		}

		// @since 2.5.6
		do_action( 'wd_recaptcha_extra_assets' );
		wp_localize_script(
			$handle,
			'WPDEF',
			array(
				'options' => $this->provider->get_options(),
				'vars'    => array(
					'visibility' => ( 'login_footer' === current_filter() ),
				),
			)
		);
	}

	/**
	 * Removes duplicate CAPTCHA scripts.
	 *
	 * @return void
	 */
	public function remove_duplicate_captcha_scripts(): void {
		global $wp_scripts;

		if ( ! is_object( $wp_scripts ) ) {
			return;
		}

		$excluded_handles = $this->provider->get_duplicate_script_handles();
		$search_pattern   = $this->provider->get_duplicate_script_pattern();
		foreach ( $wp_scripts->registered as $script_name => $args ) {
			if ( is_string( $args->src ) && preg_match( $search_pattern, $args->src ) && ! in_array( $script_name, $excluded_handles, true ) ) {
				wp_dequeue_script( $script_name );
			}
		}
	}

	/**
	 * Display the CAPTCHA field.
	 *
	 * @return void
	 */
	public function display_login_captcha(): void {
		if ( in_array( $this->provider->type, array( 'v2_checkbox', Captcha_Model::TURNSTILE ), true ) ) {
			$from_width = 302; ?>
			<style media="screen">
				.login-action-login #loginform,
				.login-action-lostpassword #lostpasswordform,
				.login-action-register #registerform {
					width: <?php echo esc_attr( $from_width ); ?>px !important;
				}

				#login_error,
				.message {
					width: <?php echo esc_attr( $from_width + 20 ); ?>px !important;
				}

				.login-action-login #loginform .captcha_wrap,
				.login-action-lostpassword #lostpasswordform .captcha_wrap,
				.login-action-register #registerform .captcha_wrap {
					margin-bottom: 10px;
				}

				#group-create-body .captcha_wrap {
					margin-top: 15px;
				}
			</style>
			<?php
		} elseif ( 'v2_invisible' === $this->provider->type ) {
			?>
			<style>
				.login-action-lostpassword #lostpasswordform .captcha_wrap,
				.login-action-login #loginform .captcha_wrap,
				.login-action-register #registerform .captcha_wrap {
					margin-bottom: 10px;
				}

				#signup-content .captcha_wrap,
				#group-create-body .captcha_wrap {
					margin-top: 10px;
				}
			</style>
			<?php
		}
		echo wp_kses( $this->display_recaptcha(), $this->get_allowed_html() );
	}

	/**
	 * Display the output of the recaptcha.
	 *
	 * @return string
	 */
	protected function display_recaptcha(): string {
		$content = $this->provider->render_widget();
		// Register reCAPTCHA script.
		$locations = $this->model->locations;
		if ( ! wp_script_is( 'wpdef_captcha_api', 'registered' ) ) {
			$script = $this->provider->get_api_script();
			wp_register_script( 'wpdef_captcha_api', $script['url'], $script['deps'], $script['version'], false );
			add_action( 'wp_footer', array( $this, 'add_captcha_scripts' ) );
			if ( in_array( self::DEFAULT_LOGIN_FORM, $locations, true ) || in_array( self::DEFAULT_REGISTER_FORM, $locations, true ) || in_array( self::DEFAULT_LOST_PASSWORD_FORM, $locations, true ) ) {
				add_action( 'login_footer', array( $this, 'add_captcha_scripts' ) );
			}
		}

		return $content;
	}

	/**
	 * Get allowed HTML tags and attributes for reCaptcha output sanitization.
	 *
	 * @return array
	 */
	private function get_allowed_html(): array {
		return array(
			'div'      => array(
				'class' => array(),
				'id'    => array(),
				'style' => array(),
			),
			'iframe'   => array(
				'src'         => array(),
				'frameborder' => array(),
				'scrolling'   => array(),
				'style'       => array(),
			),
			'noscript' => array(),
			'textarea' => array(
				'name'  => array( 'g-recaptcha-response' ),
				'class' => array( 'g-recaptcha-response' ),
				'style' => array(),
			),
			'input'    => array(
				'type'  => array( 'hidden' ),
				'class' => array( 'g-recaptcha-response' ),
				'name'  => array( 'g-recaptcha-response' ),
			),
		);
	}

	/**
	 * Validates the CAPTCHA response for the login form.
	 *
	 * @param null|WP_Error $error WP_Error object if validation fails, else null.
	 *
	 * @return null|WP_Error WP_Error object if validation fails else null.
	 */
	public function validate_login_captcha( $error ) {
		$post_data = defender_get_data_from_request( null, 'p' );
		if ( array() === $post_data ) {
			return $error;
		}
		// Skip turnstile verification for current sprint plan.
		if ( $this->provider->should_skip_check( $this->woo, $this->buddypress ) ) {
			return $error;
		}
		// Check if the $_POST array is not empty and if 'g-recaptcha-response' key is also empty.
		$captcha_response = $this->provider->get_response();
		if ( '' === $captcha_response ) {
			$code    = 'captcha_error';
			$message = __( 'Please verify that you are not a robot.', 'defender-security' );

			if ( is_wp_error( $error ) ) {
				$error->add( $code, $message );
			} else {
				// Replace $user with a new WP_Error object with an error message.
				$error = new WP_Error( $code, $message );
			}
		}

		// Return the $error variable.
		return $error;
	}

	/**
	 * Verify the captcha code on the Login page.
	 *
	 * @param WP_User|WP_Error $user WP_User or WP_Error object if a previous callback failed authentication.
	 *
	 * @return WP_Error|WP_User
	 */
	public function validate_captcha_field_on_login( $user ) {
		if ( $this->woo && $this->woo->is_woocommerce_page() ) {
			return $user;
		}
		// Skip check if connecting to XMLRPC.
		if ( defined( 'XMLRPC_REQUEST' ) ) {
			return $user;
		}
		// Skip turnstile verification for current sprint plan.
		if ( $this->provider->should_skip_check( $this->woo, $this->buddypress ) ) {
			return $user;
		}
		// Is Recaptcha-request from 'Ultimate Member' plugin?
		$um_request = defender_get_data_from_request( 'um_request', 'p' );
		if ( is_string( $um_request ) && '' !== $um_request && function_exists( 'um_recaptcha_validate' ) ) {
			return $user;
		}

		if ( ! $this->provider->verify_response( 'default_login' ) ) {
			if ( is_wp_error( $user ) ) {
				$user->add( 'invalid_captcha', $this->provider->error_message() );

				return $user;
			}

			return new WP_Error( 'invalid_captcha', $this->provider->error_message() );
		}

		return $user;
	}

	/**
	 * Verify the recaptcha code on the Registration page.
	 *
	 * @param WP_Error $errors A WP_Error object containing any errors encountered during registration.
	 *
	 * @return WP_Error
	 */
	public function validate_captcha_field_on_registration( WP_Error $errors ) {
		// Skip check if connecting to XMLRPC.
		if ( defined( 'XMLRPC_REQUEST' ) ) {
			return $errors;
		}

		if ( ! $this->provider->verify_response( 'default_registration' ) ) {
			$errors->add( 'invalid_captcha', $this->provider->error_message() );
		}
		$_POST['g-recaptcha-response-check'] = true;

		return $errors;
	}

	/**
	 * Add captcha to the multisite signup form.
	 *
	 * @param WP_Error $errors A WP_Error object possibly containing 'blogname' or 'blog_title' errors.
	 *
	 * @return void
	 */
	public function display_signup_captcha( WP_Error $errors ): void {
		$error_message = $errors->get_error_message( 'invalid_captcha' );
		if ( is_string( $error_message ) && '' !== $error_message ) {
			printf( '<p class="error">%s</p>', wp_kses_post( $error_message ) );
		}
		echo wp_kses( $this->display_recaptcha(), $this->get_allowed_html() );
	}

	/**
	 * Verify the recaptcha code on the multisite signup page.
	 *
	 * @param array $result An array of errors.
	 *
	 * @return array
	 */
	public function validate_captcha_field_on_wpmu_registration( array $result ): array {
		global $current_user;
		if ( is_admin() && ! defined( 'DOING_AJAX' ) && isset( $current_user->data->ID ) && 0 < (int) $current_user->data->ID ) {
			return $result;
		}

		// Skip if BuddyPress is handling the registration.
		if ( $this->buddypress && $this->buddypress->is_activated() && in_array( Buddypress::REGISTER_FORM, $this->model->buddypress_checked_locations, true ) ) {
			return $result;
		}

		if ( ! $this->provider->verify_response( 'wpmu_registration' ) ) {
			if ( isset( $result['errors'] ) && $result['errors'] instanceof WP_Error ) {
				$errors = $result['errors'];
			} else {
				$errors = new WP_Error();
			}
			$errors->add( 'invalid_captcha', $this->provider->error_message() );
			$result['errors'] = $errors;

			return $result;
		}

		return $result;
	}

	/**
	 * Verify the recaptcha code on Woo login page.
	 *
	 * @param WP_Error $errors A WP_Error object containing any errors encountered during login.
	 *
	 * @return WP_Error
	 */
	public function validate_captcha_field_on_woo_login( WP_Error $errors ) {
		// Skip check if connecting to XMLRPC.
		if ( defined( 'XMLRPC_REQUEST' ) ) {
			return $errors;
		}

		if ( ! $this->provider->verify_response( 'woo_login' ) ) {
			// Remove 'Error: ' because Woo has it by default.
			$message = str_replace( sprintf( '<strong>%s:</strong> ', esc_html__( 'Error', 'defender-security' ) ), '', $this->provider->error_message() );
			$errors->add( 'invalid_captcha', $message );
		}

		return $errors;
	}

	/**
	 * Check recaptcha on Woo registration form.
	 *
	 * @param WP_Error $errors A WP_Error object containing any errors encountered during registration.
	 *
	 * @return WP_Error
	 */
	public function validate_captcha_field_on_woo_registration( WP_Error $errors ) {
		if ( defined( 'WOOCOMMERCE_CHECKOUT' ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return $errors;
		}
		if ( ! $this->provider->verify_response( 'woo_registration' ) ) {
			// Remove 'Error: ' because Woo has it by default.
			$message = str_replace( sprintf( '<strong>%s:</strong> ', esc_html__( 'Error', 'defender-security' ) ), '', $this->provider->error_message() );
			$errors->add( 'invalid_captcha', $message );
		}

		return $errors;
	}

	/**
	 * Fires before errors are returned from a password reset request.
	 * Without 2nd `$user_data` parameter because it's since WP 5.4.0.
	 *
	 * @param WP_Error $errors A WP_Error object containing any errors encountered during password reset.
	 *
	 * @return void
	 */
	public function validate_captcha_field_on_lostpassword( WP_Error $errors ): void {
		if ( ! $this->provider->verify_response( 'default_lost_password' ) ) {
			$errors->add( 'invalid_captcha', $this->provider->error_message() );
		}
	}

	/**
	 * Validates the reCAPTCHA field on the WooCommerce checkout form.
	 *
	 * @param array    $fields The fields of the checkout form.
	 * @param WP_Error $errors The errors encountered during the checkout process.
	 *
	 * @return void
	 */
	public function validate_captcha_field_on_woo_checkout( $fields, $errors ): void {
		if ( ! $this->provider->verify_response( 'woo_checkout' ) ) {
			// Remove 'Error: ' because Woo has it by default.
			$message = str_replace( sprintf( '<strong>%s:</strong> ', esc_html__( 'Error', 'defender-security' ) ), '', $this->provider->error_message() );
			$errors->add( 'invalid_captcha', $message );
		}
	}

	/**
	 * Display google recaptcha on comments form.
	 *
	 * @param array $defaults The default comment form arguments.
	 *
	 * @return array
	 */
	public function comment_form_defaults( array $defaults ) {
		$defaults['comment_notes_after'] .= '<p>' . $this->display_recaptcha() . '</p>';

		return $defaults;
	}

	/**
	 * Check JS enabled for comment form.
	 *
	 * @param int $comment_post_id Post ID.
	 *
	 * @return void
	 */
	public function validate_captcha_field_on_comment( $comment_post_id ) {
		if ( $this->exclude_captcha_for_requests() ) {
			return;
		}
		// Skip if it's from WooCommerce review form.
		if ( 'product' === get_post_type( $comment_post_id ) ) {
			return;
		}

		if ( ! $this->provider->verify_response( 'default_comments' ) ) {
			// @since v2.5.6
			wp_die( wp_kses_post( apply_filters( 'wd_recaptcha_require_valid_comment', $this->provider->error_message() ) ) );
		}
	}

	/**
	 * Excludes CAPTCHA for specific requests.
	 *
	 * @return bool
	 */
	public function exclude_captcha_for_requests(): bool {
		$uri               = defender_get_data_from_request( 'REQUEST_URI', 's' ) ?? '/';
		$excluded_requests = $this->provider->get_excluded_requests();

		return in_array( $uri, $excluded_requests, true );
	}

	/**
	 * Display the BuddyPress reCAPTCHA.
	 *
	 * @return void
	 */
	public function display_buddypress_recaptcha(): void {
		$error = '';

		if ( function_exists( 'buddypress' ) ) {
			$obj = buddypress();
			if ( isset( $obj->signup->errors['failed_captcha_verification'] ) && '' !== $obj->signup->errors['failed_captcha_verification'] ) {
				$error = $obj->signup->errors['failed_captcha_verification'];
			}
		}

		if ( '' !== $error ) {
			$output  = '<div class="error">';
			$output .= $error;
			$output .= '</div>';

			echo wp_kses_post( $output );
		}

		echo wp_kses( $this->display_recaptcha(), $this->get_allowed_html() );
	}

	/**
	 * Validates the reCAPTCHA field on the BuddyPress registration form.
	 *
	 * @return void
	 */
	public function validate_captcha_field_on_buddypress_registration(): void {
		if ( ! $this->provider->verify_response( 'buddypress_registration' ) && function_exists( 'buddypress' ) ) {
			buddypress()->signup->errors['failed_captcha_verification'] = $this->provider->error_message();
		}
	}

	/**
	 * Verify BuddyPress group form captcha.
	 *
	 * @return void
	 */
	public function validate_captcha_field_on_buddypress_group(): void {
		if ( function_exists( 'bp_is_group_creation_step' ) && ! bp_is_group_creation_step( 'group-details' ) ) {
			return;
		}

		if (
			! $this->provider->verify_response( 'buddypress_create_group' )
			&& function_exists( 'bp_core_add_message' )
			&& function_exists( 'bp_core_redirect' )
			&& function_exists( 'bp_get_root_domain' )
			&& function_exists( 'bp_get_groups_root_slug' )
		) {
			bp_core_add_message( $this->provider->error_message(), 'error' );
			bp_core_redirect( bp_get_root_domain() . '/' . bp_get_groups_root_slug() . '/create/step/group-details/' );
		}
	}
}
