<?php
/**
 * Manages notification recipients.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Event;
use Calotes\Helper\HTTP;
use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Component\Recipient_Directory;
use WP_Defender\Component\Recipient_Verification;

/**
 * Handles recipient routes.
 */
class Recipients extends Event {

	/**
	 * Route slug.
	 *
	 * @var string
	 */
	protected $slug = 'wdf-recipients';

	/**
	 * Notification service.
	 *
	 * @var \WP_Defender\Component\Notification
	 */
	protected $service;

	/**
	 * Recipient service.
	 *
	 * @var \WP_Defender\Component\Recipients
	 */
	protected $recipient_service;

	/**
	 * Recipient directory service.
	 *
	 * @var Recipient_Directory
	 */
	protected $recipient_directory;

	/**
	 * Recipient verification service.
	 *
	 * @var Recipient_Verification
	 */
	protected $recipient_verification;

	/**
	 * Register routes and hooks.
	 */
	public function __construct() {
		$this->register_routes();
		$this->service                = wd_di()->get( \WP_Defender\Component\Notification::class );
		$this->recipient_service      = wd_di()->get( \WP_Defender\Component\Recipients::class );
		$this->recipient_directory    = wd_di()->get( Recipient_Directory::class );
		$this->recipient_verification = wd_di()->get( Recipient_Verification::class );
		add_action( 'wp_ajax_' . Notification::SLUG_SUBSCRIBE, array( $this, 'verify_subscriber' ) );
		add_action( 'wp_ajax_nopriv_' . Notification::SLUG_SUBSCRIBE, array( $this, 'verify_subscriber' ) );
	}

	/**
	 * Add a recipient to selected notification modules.
	 *
	 * @param Request $request Request data.
	 * @return Response Response data.
	 * @defender_route
	 */
	public function add_recipient( Request $request ): Response {
		if ( ! $this->check_permission() ) {
			return new Response( false, array( 'message' => esc_html__( 'You do not have permission to perform this action.', 'defender-security' ) ) );
		}

		$data = $request->get_data(
			array(
				'name'     => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'email'    => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_email',
				),
				'statuses' => array( 'type' => 'array' ),
				'_inHouse' => array( 'type' => 'bool' ),
				'id'       => array( 'type' => 'integer' ),
			)
		);

		$name     = trim( (string) ( $data['name'] ?? '' ) );
		$email    = trim( (string) ( $data['email'] ?? '' ) );
		$statuses = array_map( 'sanitize_key', is_array( $data['statuses'] ?? null ) ? $data['statuses'] : array() );
		$user_id  = absint( $data['id'] ?? 0 );
		$in_house = (bool) ( $data['_inHouse'] ?? false ) && $user_id > 0;

		if ( '' === $name || ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid recipient data.', 'defender-security' ) ) );
		}

		if ( ! $in_house && ! preg_match( '/^[\p{L}\s\-\']+$/u', $name ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Only letters, spaces, hyphens and apostrophes allowed.', 'defender-security' ) ) );
		}

		if ( empty( $statuses ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Please enable at least one notification module before inviting a recipient.', 'defender-security' ) ) );
		}

		$subscriber = array(
			'name'  => $name,
			'email' => $email,
		);
		if ( $in_house ) {
			$subscriber['id'] = $user_id;
		}

		$this->recipient_service->upsert_recipient_to_modules( $statuses, $subscriber );

		return new Response( true, $this->data_frontend() );
	}

	/**
	 * Update a recipient across notification modules.
	 *
	 * @param Request $request Request.
	 * @return Response Response data.
	 * @defender_route
	 */
	public function update_recipient( Request $request ): Response {
		if ( ! $this->check_permission() ) {
			return new Response( false, array( 'message' => esc_html__( 'You do not have permission to perform this action.', 'defender-security' ) ) );
		}

		$data = $request->get_data(
			array(
				'id'           => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'statuses'     => array( 'type' => 'array' ),
				'profile'      => array( 'type' => 'array' ),
				'unsubscribed' => array( 'type' => 'array' ),
			)
		);

		$recipient_id = trim( (string) ( $data['id'] ?? '' ) );
		$statuses     = array_map( 'sanitize_key', is_array( $data['statuses'] ?? null ) ? $data['statuses'] : array() );
		$profile      = is_array( $data['profile'] ?? null ) ? $data['profile'] : array();
		$unsubscribed = array_map( 'sanitize_key', is_array( $data['unsubscribed'] ?? null ) ? $data['unsubscribed'] : array() );

		if ( '' === $recipient_id ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid recipient ID.', 'defender-security' ) ) );
		}

		$name     = sanitize_text_field( trim( (string) ( $profile['name'] ?? '' ) ) );
		$email    = sanitize_email( trim( (string) ( $profile['email'] ?? '' ) ) );
		$in_house = is_numeric( $recipient_id );

		if ( '' === $name || ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid recipient data.', 'defender-security' ) ) );
		}

		if ( ! $in_house && ! preg_match( '/^[\p{L}\s\-\']+$/u', $name ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Only letters, spaces, hyphens and apostrophes allowed.', 'defender-security' ) ) );
		}

		$subscriber = array(
			'name'  => $name,
			'email' => $email,
		);
		if ( $in_house ) {
			$subscriber['id']         = (int) $recipient_id;
			$subscriber['first_name'] = sanitize_text_field( trim( (string) ( $profile['firstName'] ?? '' ) ) );
			$subscriber['last_name']  = sanitize_text_field( trim( (string) ( $profile['lastName'] ?? '' ) ) );
		}

		$this->recipient_service->upsert_recipient_to_modules( $statuses, $subscriber, $unsubscribed );

		return new Response( true, $this->data_frontend() );
	}

	/**
	 * Delete a recipient from all notification modules.
	 *
	 * @param Request $request Request data.
	 * @return Response Response data.
	 * @defender_route
	 */
	public function delete_recipient( Request $request ): Response {
		if ( ! $this->check_permission() ) {
			return new Response( false, array( 'message' => esc_html__( 'You do not have permission to perform this action.', 'defender-security' ) ) );
		}

		$data = $request->get_data(
			array(
				'id' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);

		$recipient_id = trim( (string) ( $data['id'] ?? '' ) );
		if ( '' === $recipient_id ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid recipient ID.', 'defender-security' ) ) );
		}

		$this->recipient_directory->delete_recipient( $recipient_id );

		return new Response( true, $this->data_frontend() );
	}

	/**
	 * Search WordPress users by name or email.
	 *
	 * @param Request $request Request data.
	 * @return Response Response data.
	 * @defender_route
	 */
	public function search_users( Request $request ): Response {
		if ( ! $this->check_permission() ) {
			return new Response( false, array( 'message' => esc_html__( 'You do not have permission to perform this action.', 'defender-security' ) ) );
		}

		$data   = $request->get_data(
			array(
				'search' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		$search = trim( (string) ( $data['search'] ?? '' ) );

		return new Response( true, array( 'users' => $this->recipient_directory->search_users( $search ) ) );
	}

	/**
	 * Resend verification email for a pending recipient.
	 *
	 * @param Request $request Request data.
	 * @return Response Response data.
	 * @defender_route
	 */
	public function resend_verification( Request $request ): Response {
		if ( ! $this->check_permission() ) {
			return new Response( false, array( 'message' => esc_html__( 'You do not have permission to perform this action.', 'defender-security' ) ) );
		}

		$data = $request->get_data(
			array(
				'id'      => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'pending' => array( 'type' => 'array' ),
			)
		);

		$result = $this->recipient_verification->resend_verification( $data );

		return new Response( $result['success'], $result['data'] );
	}

	/**
	 * Confirm a subscriber from an email link.
	 *
	 * @return void
	 */
	public function verify_subscriber(): void {
		$hash    = HTTP::get( 'hash', '' );
		$slug    = HTTP::get( 'uid', '' );
		$uids    = HTTP::get( 'uids', '' );
		$inhouse = HTTP::get( 'inhouse', '0' );

		if ( '1' === $inhouse && ! is_user_logged_in() ) {
			auth_redirect();
		}
		if ( ! is_string( $hash ) || '' === trim( $hash ) ) {
			wp_die( esc_html__( 'You shall not pass.', 'defender-security' ) );
		}

		$slugs = $this->recipient_verification->parse_subscription_slugs( $slug, $uids );
		if ( array() === $slugs ) {
			wp_die( esc_html__( 'You shall not pass.', 'defender-security' ) );
		}

		$is_bulk = is_string( $uids ) && '' !== trim( $uids );
		$result  = $this->recipient_verification->confirm_subscriptions( $slugs, $hash, $inhouse, $is_bulk );

		if ( ! $result['found_module'] ) {
			wp_die( esc_html__( 'You shall not pass.', 'defender-security' ) );
		}

		$this->redirect_after_verify( $inhouse, $result );
		exit; // Required after wp_safe_redirect().
	}

	/**
	 * Redirect the user after subscription verification.
	 *
	 * @param string $inhouse Whether the recipient is in-house ('1' or '0').
	 * @param array  $result  Confirmation result from recipient service.
	 * @return void
	 */
	private function redirect_after_verify( string $inhouse, array $result ): void {
		if ( '1' === $inhouse && $result['processed'] ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'slug'    => $result['redirect_slug'],
						'context' => 'subscribed',
					),
					get_edit_profile_url()
				)
			);
		} elseif ( $result['processed'] ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'defender_subscription' => 'confirmed',
						'slug'                  => $result['redirect_slug'],
						'hash'                  => HTTP::get( 'hash', '' ),
					),
					home_url()
				)
			);
		} else {
			wp_safe_redirect( home_url() );
		}
	}

	/**
	 * Get recipient data for the frontend.
	 *
	 * @return array Frontend recipient data.
	 */
	public function data_frontend(): array {
		return array_merge(
			$this->dump_routes_and_nonces(),
			array(
				'recipients'    => $this->recipient_directory->get_all_recipients(),
				'notifications' => $this->service->get_modules(),
			)
		);
	}

	/**
	 * Remove saved settings.
	 *
	 * @return void
	 */
	public function remove_settings(): void {
	}

	/**
	 * Remove stored data.
	 *
	 * @return void
	 */
	public function remove_data(): void {
	}

	/**
	 * Export controller data.
	 *
	 * @return array Exported controller data.
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Import controller data.
	 *
	 * @param array $data Import data.
	 * @return void
	 */
	public function import_data( array $data ): void {
	}

	/**
	 * Get translatable strings.
	 *
	 * @return array Translatable strings.
	 */
	public function export_strings(): array {
		return array();
	}
}
