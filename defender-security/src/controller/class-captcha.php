<?php
/**
 * Handles Captcha related actions.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Event;
use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Integrations\Hummingbird;
use WP_Defender\Integrations\Buddypress;
use WP_Defender\Integrations\Woocommerce;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Component\Captcha as Captcha_Component;
use WP_Defender\Model\Setting\Captcha as Captcha_Model;

/**
 * Handles Captcha related actions.
 *
 * @since 2.5.4
 */
class Captcha extends Event {

	/**
	 * The model for handling the data.
	 *
	 * @var Captcha_Model
	 */
	public $model;
	/**
	 * Service for handling logic.
	 *
	 * @var Captcha_Component
	 */
	protected $service;

	/**
	 * Is Woo activated.
	 *
	 * @var bool
	 */
	private $is_woo_activated;

	/**
	 * Is BuddyPress activated.
	 *
	 * @var bool
	 */
	private $is_buddypress_activated;

	/**
	 * Buddypress integration module.
	 *
	 * @var Buddypress|null
	 */
	private ?Buddypress $buddypress;

	/**
	 * Woocommerce integration module.
	 *
	 * @var Woocommerce|null
	 */
	private ?Woocommerce $woo;

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 */
	public function __construct() {
		$this->model = wd_di()->get( Captcha_Model::class );

		$this->service = new Captcha_Component( $this->model );
		$this->register_routes();
		$this->woo                     = wd_di()->get( Woocommerce::class );
		$this->is_woo_activated        = $this->woo->is_activated();
		$this->buddypress              = wd_di()->get( Buddypress::class );
		$this->is_buddypress_activated = $this->buddypress->is_activated();
		add_filter( 'wp_defender_advanced_tools_data', array( $this, 'script_data' ) );

		if ( $this->model->is_active() // No need the check by Woo and Buddypress are activated because we use this below.
			&& $this->service->enable_any_location( $this->is_woo_activated, $this->is_buddypress_activated ) && ! $this->service->exclude_captcha_for_requests() ) {
			$this->add_actions();

			add_filter( 'script_loader_tag', array( $this->service, 'script_loader_tag' ), 10, 2 );
		}
	}

	/**
	 * Add actions for CAPTCHA.
	 *
	 * @return void
	 */
	protected function add_actions() {
		$extra_conditions = is_admin() && ! ( defined( 'DOING_AJAX' ) && $this->is_captcha_settings() );
		// Since v5.7.0.
		do_action( 'wd_captcha_before_actions', $extra_conditions );

		do_action_deprecated( 'wd_recaptcha_before_actions', array( $extra_conditions ), '5.7.0', 'wd_captcha_before_actions', __( 'This hook is deprecated and will be removed in future versions.', 'defender-security' ) );
		if ( $extra_conditions ) {
			return;
		}

		$display_for_known_users = $this->model->display_for_known_users();
		$locations               = $this->model->locations;
		if ( in_array( Captcha_Component::DEFAULT_LOGIN_FORM, $locations, true ) || in_array( Captcha_Component::DEFAULT_REGISTER_FORM, $locations, true ) || in_array( Captcha_Component::DEFAULT_LOST_PASSWORD_FORM, $locations, true ) ) {
			add_filter( 'cfturnstile_widget_disable', '__return_true' );
			add_filter( 'easy_cloudflare_turnstile_render_list', '__return_empty_array' );
			add_filter( 'easy_cloudflare_turnstile_verify_list', '__return_empty_array' );
			add_action(
				'login_enqueue_scripts',
				array(
					$this->service,
					'remove_duplicate_captcha_scripts',
				),
				PHP_INT_MAX
			);
		}
		// Default login form.
		if ( in_array( Captcha_Component::DEFAULT_LOGIN_FORM, $locations, true ) ) {
			add_filter( 'authenticate', array( $this->service, 'validate_login_captcha' ), 9999 );
			add_action( 'login_form', array( $this->service, 'display_login_captcha' ) );
			add_filter( 'wp_authenticate_user', array( $this->service, 'validate_captcha_field_on_login' ), 8 );
		}
		// Default register form.
		if ( in_array( Captcha_Component::DEFAULT_REGISTER_FORM, $locations, true ) ) {
			if ( ! is_multisite() ) {
				add_action( 'register_form', array( $this->service, 'display_login_captcha' ) );
				add_filter(
					'registration_errors',
					array(
						$this->service,
						'validate_captcha_field_on_registration',
					),
					10
				);
			} else {
				add_action( 'signup_extra_fields', array( $this->service, 'display_signup_captcha' ) );
				add_action( 'signup_blogform', array( $this->service, 'display_signup_captcha' ) );
				add_filter(
					'wpmu_validate_user_signup',
					array(
						$this->service,
						'validate_captcha_field_on_wpmu_registration',
					),
					10
				);
			}
		}
		// Default lost password form.
		if ( in_array( Captcha_Component::DEFAULT_LOST_PASSWORD_FORM, $locations, true ) ) {
			add_action( 'lostpassword_form', array( $this->service, 'display_login_captcha' ) );
			if ( $this->maybe_validate_captcha_for_lostpassword() ) {
				add_action( 'lostpassword_post', array( $this->service, 'validate_captcha_field_on_lostpassword' ) );
			}
		}
		// Default comment form.
		if ( $display_for_known_users && in_array( Captcha_Component::DEFAULT_COMMENT_FORM, $locations, true ) ) {
			// @since v3.4.0 Change from 'comment_form_after_fields' to 'comment_form_defaults'.
			add_filter( 'comment_form_defaults', array( $this->service, 'comment_form_defaults' ), 10 );
			add_action( 'pre_comment_on_post', array( $this->service, 'validate_captcha_field_on_comment' ) );
			// When comments are loaded via Hummingbird's lazy load feature.
			if ( wd_di()->get( Hummingbird::class )->is_lazy_load_comments_enabled() ) {
				add_action( 'wp_footer', array( $this->service, 'add_scripts_for_lazy_load' ) );
			}
		}
		// Todo: move code to related class.
		// For Woo forms. Mandatory check for the activated Woo before.
		if ( $this->model->check_woo_locations( $this->is_woo_activated ) ) {
			$woo_locations = $this->model->woo_checked_locations;
			// Woo login form.
			if ( in_array( Woocommerce::WOO_LOGIN_FORM, $woo_locations, true ) ) {
				add_action( 'woocommerce_login_form', array( $this->service, 'display_login_captcha' ) );
				add_filter(
					'woocommerce_process_login_errors',
					array(
						$this->service,
						'validate_captcha_field_on_woo_login',
					),
					10
				);
			}
			// Woo register form.
			if ( in_array( Woocommerce::WOO_REGISTER_FORM, $woo_locations, true ) ) {
				add_action( 'woocommerce_register_form', array( $this->service, 'display_login_captcha' ) );
				add_filter(
					'woocommerce_registration_errors',
					array(
						$this->service,
						'validate_captcha_field_on_woo_registration',
					),
					10
				);
			}
			// Woo lost password form.
			if ( in_array( Woocommerce::WOO_LOST_PASSWORD_FORM, $woo_locations, true ) ) {
				add_action( 'woocommerce_lostpassword_form', array( $this->service, 'display_login_captcha' ) );
				// Use default WP hook because Woo doesn't have own hook, so there's the extra check for Woo form.
				$post_data = defender_get_data_from_request( null, 'p' );
				if ( isset( $post_data['wc_reset_password'], $post_data['user_login'] ) ) {
					add_action(
						'lostpassword_post',
						array(
							$this->service,
							'validate_captcha_field_on_lostpassword',
						)
					);
				}
			}
			// Woo checkout form.
			if ( $display_for_known_users && in_array( Woocommerce::WOO_CHECKOUT_FORM, $woo_locations, true ) ) {
				add_action(
					'woocommerce_after_checkout_billing_form',
					array(
						$this->service,
						'display_login_captcha',
					)
				);
				add_action(
					'woocommerce_after_checkout_validation',
					array(
						$this->service,
						'validate_captcha_field_on_woo_checkout',
					),
					10,
					2
				);
			}
		}
		// For BuddyPress forms. Mandatory check for the activated BuddyPress before.
		if ( $this->model->check_buddypress_locations( $this->is_buddypress_activated ) ) {
			$buddypress_locations = $this->model->buddypress_checked_locations;
			// Register form.
			if ( in_array( Buddypress::REGISTER_FORM, $buddypress_locations, true ) ) {
				add_action(
					'bp_before_registration_submit_buttons',
					array(
						$this->service,
						'display_buddypress_recaptcha',
					)
				);
				add_action(
					'bp_signup_validate',
					array(
						$this->service,
						'validate_captcha_field_on_buddypress_registration',
					),
					10
				);
			}
			// Group form.
			if ( $display_for_known_users && in_array( Buddypress::NEW_GROUP_FORM, $buddypress_locations, true ) ) {
				add_action( 'bp_after_group_details_creation_step', array( $this->service, 'display_login_captcha' ) );
				add_action(
					'groups_group_before_save',
					array(
						$this->service,
						'validate_captcha_field_on_buddypress_group',
					)
				);
			}
		}
		// Since v5.7.0.
		do_action( 'wd_captcha_after_actions', $display_for_known_users );

		do_action_deprecated( 'wd_recaptcha_after_actions', array( $display_for_known_users ), '5.7.0', 'wd_captcha_after_actions', __( 'This hook is deprecated and will be removed in a future version.', 'defender-security' ) );
	}

	/**
	 * Is it Defender's CAPTCHA page?
	 *
	 * @return bool
	 */
	protected function is_captcha_settings(): bool {
		$view = defender_get_data_from_request( 'view', 'g' );

		return 'wdf-advanced-tools' === defender_get_current_page() && 'captcha' === $view;
	}

	/**
	 * Maybe validate reCaptcha for lost password.
	 *
	 * @return bool
	 * @since 3.2.0
	 */
	protected function maybe_validate_captcha_for_lostpassword(): bool {
		$post_data = defender_get_data_from_request( null, 'p' );
		$action    = $post_data['action'] ?? '';

		return ! $this->is_woocommerce_page() && ! isset( $post_data['wc_reset_password'], $post_data['user_login'] ) && ! ( is_admin() && 'send-password-reset' === $action ) && 'pp_ajax_passwordreset' !== $action;
	}

	/**
	 * Check the current page from is from the Woo plugin.
	 *
	 * @return bool
	 */
	protected function is_woocommerce_page(): bool {
		if ( ! $this->is_woo_activated ) {
			return false;
		}

		$traces = debug_backtrace(); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
		foreach ( $traces as $trace ) {
			if ( isset( $trace['file'] ) && false !== strpos( $trace['file'], 'woocommerce' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Provide data to the frontend via localized script.
	 *
	 * @param array $data Data collection is ready to passed.
	 *
	 * @return array Modified data array with added this controller data.
	 */
	public function script_data( array $data ): array {
		$data['captcha'] = $this->data_frontend();

		return $data;
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		$model       = $this->model;
		$is_active   = $model->is_active();
		$notice_data = $this->service->get_provider()->get_notice_data(
			$this->is_woo_activated,
			$this->is_buddypress_activated
		);

		/**
		 * Cases:
		 * Invalid domain for Site Key,
		 * Google ReCAPTCHA is in localhost,
		 * Cannot contact reCAPTCHA. Check your connection.
		 */
		$ticket_text = esc_html__( 'If you see any errors in the preview, make sure the keys you’ve entered are valid, and you\'ve listed your domain name while generating the keys.', 'defender-security' );

		if ( ( new WPMUDEV() )->show_support_links() ) {
			$ticket_text .= defender_support_ticket_text();
		}

		return array_merge(
			array(
				'model'                     => $model->export(),
				'active_captcha'            => $model->get_active_captcha_data(),
				'is_active'                 => $is_active,
				'default_message'           => $this->model->get_default_values()['message'],
				'default_turnstile_message' => $this->model->get_default_values()['turnstile_message'],
				'default_locations'         => Captcha_Component::get_forms(),
				'notice_type'               => $notice_data['notice_type'],
				'notice_text'               => $notice_data['notice_text'],
				'ticket_text'               => $ticket_text,
				'is_woo_active'             => $this->woo->is_activated(),
				'woo_locations'             => Woocommerce::get_forms(),
				'is_buddypress_active'      => $this->buddypress->is_activated(),
				'buddypress_locations'      => Buddypress::get_forms(),
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Save settings.
	 *
	 * @param Request $request The request object containing new settings data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_settings( Request $request ): Response {
		$data     = $request->get_data_by_model( $this->model );
		$old_data = $this->model->get_active_captcha_data( $data['provider'], $data['active_type'] );
		$this->model->import( $data );
		if ( Captcha_Model::TURNSTILE === $this->model->provider ) {
			$this->model->active_type = Captcha_Model::TURNSTILE;
		}
		$new_data   = $this->model->get_active_captcha_data();
		$old_key    = $old_data['key'] ?? '';
		$old_secret = $old_data['secret'] ?? '';
		$key        = $new_data['key'] ?? '';
		$secret     = $new_data['secret'] ?? '';
		$provider   = $this->service->get_provider();
		$is_valid   = ( '' === $secret && '' === $key ) || ( '' !== $secret && '' !== $key );
		if ( ( $old_key !== $key || $old_secret !== $secret ) && '' !== $secret && '' !== $key ) {
			$valid_token = $request->get_data(
				array(
					'token' => array(
						'type' => 'string',
					),
				)
			);
			$token       = $valid_token['token'] ?? '';
			if ( '' === $token ) {
				$is_valid = false;
			} else {
				$response = $provider->verify_response_token(
					$token,
					$provider->get_verify_url(),
					array(
						'secret' => $secret,
					)
				);
				$is_valid = isset( $response['success'] ) && true === $response['success'];
			}
		}
		if ( ! $is_valid ) {
			return new Response(
				false, // Merge stored data to avoid errors.
				array_merge(
					array(
						'message'    => sprintf(
						/* translators: Provider label. */
							__( 'Please make sure your %s API keys are correct and that Preview Widget verification is successful.', 'defender-security' ),
							Captcha_Model::TURNSTILE === $this->model->provider ? __( 'Cloudflare', 'defender-security' ) : __( 'reCAPTCHA', 'defender-security' )
						),
						'error_keys' => array( 'invalid-secret' ),
					),
					$this->data_frontend()
				)
			);
		}

		if ( $this->model->validate() ) {
			$this->model->save();
			Config_Hub_Helper::set_clear_active_flag();

			return new Response(
				true,
				array_merge(
					array(
						'message'    => esc_html__( 'Settings saved successfully!', 'defender-security' ),
						'auto_close' => true,
					),
					$this->data_frontend()
				)
			);
		}

		return new Response(
			false, // Merge stored data to avoid errors.
			array_merge(
				array(
					'message'    => $this->model->get_formatted_errors(),
					'error_keys' => $this->model->get_error_keys(),
				),
				$this->data_frontend()
			)
		);
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings() {
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data(): void {
		$this->model->delete();
	}

	/**
	 * Converts the current object state to an array.
	 *
	 * @return array The array representation of the object.
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Provides data for the dashboard widget.
	 *
	 * @return array An array of dashboard widget data.
	 */
	public function dashboard_widget(): array {
		$model       = $this->model;
		$notice_type = ( $model->is_active() && $this->service->enable_any_location( $this->is_woo_activated, $this->is_buddypress_activated ) ) ? 'success' : 'warning';

		return array(
			'model'       => $model->export(),
			'notice_type' => $notice_type,
		);
	}

	/**
	 * Imports data into the model.
	 *
	 * @param array $data Data to be imported into the model.
	 */
	public function import_data( array $data ) {
		$model = $this->model;

		$model->import( $data );
		if ( $model->validate() ) {
			$model->save();
		}
	}

	/**
	 * Exports strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		return array( $this->model->is_active() ? esc_html__( 'Active', 'defender-security' ) : esc_html__( 'Inactive', 'defender-security' ) );
	}

	/**
	 * Enable/disable module.
	 *
	 * @param Request $request The request object.
	 *
	 * @return Response
	 * @defender_route
	 * @since 3.12.0
	 */
	public function toggle_module( Request $request ): Response {
		$data                 = $request->get_data(
			array(
				'enabled' => array(
					'type' => 'boolean',
				),
			)
		);
		$prev_state           = $this->model->enabled;
		$this->model->enabled = $data['enabled'];
		$this->model->save();
		$message = esc_html__( 'Settings saved successfully!', 'defender-security' );
		if ( $prev_state !== $data['enabled'] ) {
			if ( $data['enabled'] ) {
				$message = esc_html__( 'CAPTCHA module is enabled successfully!', 'defender-security' );
			} else {
				$message = esc_html__( 'CAPTCHA module is disabled successfully!', 'defender-security' );
			}
		}

		Config_Hub_Helper::set_clear_active_flag();

		return new Response(
			true,
			array_merge(
				array(
					'message'    => $message,
					'auto_close' => true,
				),
				$this->data_frontend()
			)
		);
	}
}
