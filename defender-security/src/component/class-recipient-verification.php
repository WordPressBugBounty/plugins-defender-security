<?php
/**
 * Manages recipient verification for notification modules.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Model\Notification as Model_Notification;
use WP_Defender\Traits\User;

/**
 * Handles recipient verification and subscription confirmation.
 */
class Recipient_Verification extends Component {

	use User;

	/**
	 * Notification service.
	 *
	 * @var Notification
	 */
	private Notification $notification;

	/**
	 * Initialize dependencies.
	 */
	public function __construct() {
		$this->notification = wd_di()->get( Notification::class );
	}

	/**
	 * Process a resend-verification request.
	 *
	 * @param array $data Validated request data.
	 * @return array Result with success flag and response data.
	 */
	public function resend_verification( array $data ): array {
		$recipient_id = trim( (string) ( $data['id'] ?? '' ) );
		$raw_pending  = $data['pending'] ?? null;
		$statuses     = array_map( 'sanitize_key', is_array( $raw_pending ) ? $raw_pending : array() );

		if ( '' === $recipient_id || empty( $statuses ) ) {
			return $this->response_data( false, esc_html__( 'Invalid request.', 'defender-security' ) );
		}

		$in_house  = is_numeric( $recipient_id );
		$user_id   = $in_house ? (int) $recipient_id : 0;
		$email_key = $this->resolve_email_key( $in_house, $user_id, $recipient_id );

		$collected  = $this->collect_pending_modules( $statuses, $in_house, $email_key, $user_id );
		$subscriber = $collected['subscriber'];
		$modules    = $collected['modules'];

		if ( null === $subscriber ) {
			return $this->response_data( false, esc_html__( 'Recipient not found.', 'defender-security' ) );
		}

		if ( empty( $modules ) ) {
			return $this->response_data( false, esc_html__( 'Module not found.', 'defender-security' ) );
		}

		return $this->send_verification_email( $subscriber, $modules );
	}

	/**
	 * Parse notification slugs from query string parameters.
	 *
	 * @param mixed $slug Single uid query param.
	 * @param mixed $uids Comma-separated uids query param.
	 * @return array Sanitized slug list.
	 */
	public function parse_subscription_slugs( $slug, $uids ): array {
		if ( is_string( $uids ) && '' !== trim( $uids ) ) {
			return array_filter( array_map( 'sanitize_key', explode( ',', $uids ) ) );
		}
		if ( is_string( $slug ) && '' !== trim( $slug ) ) {
			return array( sanitize_key( $slug ) );
		}
		return array();
	}

	/**
	 * Confirm matching subscriptions.
	 *
	 * @param array  $slugs    Notification slugs.
	 * @param string $hash     Subscription hash.
	 * @param string $inhouse  Whether the request is for an in-house recipient.
	 * @param bool   $is_bulk  Whether the request came from a multi-module invite link.
	 * @return array Confirmation result data.
	 */
	public function confirm_subscriptions( array $slugs, string $hash, string $inhouse, bool $is_bulk ): array {
		$result     = $this->empty_confirmation_result();
		$group      = '1' === $inhouse ? 'in_house_recipients' : 'out_house_recipients';
		$module_map = $this->notification->get_module_map();

		foreach ( $slugs as $module_slug ) {
			$model = $module_map[ $module_slug ] ?? null;
			if ( ! $model instanceof Model_Notification ) {
				continue;
			}
			$result['found_module'] = true;

			$match = $this->confirm_recipients_in_group( $model->$group, $hash, $group );
			if ( null === $match ) {
				continue;
			}

			$model->$group = $match['recipients'];
			$model->save();

			$result['processed']     = true;
			$result['redirect_slug'] = '' === $result['redirect_slug'] ? $model->slug : $result['redirect_slug'];
			if ( $is_bulk ) {
				$result['confirmed_modules'][] = $model;
				$result['confirmed_email']     = $match['email'];
				$result['confirmed_name']      = $match['name'];
			} else {
				$this->notification->send_subscribed_email( $match['email'], $model, $match['name'] );
			}
		}

		if ( $is_bulk && array() !== $result['confirmed_modules'] ) {
			$this->notification->send_subscribed_all_email(
				$result['confirmed_email'],
				$result['confirmed_modules'],
				$result['confirmed_name']
			);
		}

		return $result;
	}

	/**
	 * Build a standard service response data shape.
	 *
	 * @param bool   $success Whether the operation succeeded.
	 * @param string $message Response message.
	 * @return array
	 */
	private function response_data( bool $success, string $message ): array {
		return array(
			'success' => $success,
			'data'    => array( 'message' => $message ),
		);
	}

	/**
	 * Collect notification modules matching the given slugs and resolve the subscriber.
	 *
	 * @param array  $statuses  Sanitized module slugs.
	 * @param bool   $in_house  Whether the recipient is a WP user.
	 * @param string $email_key Email key for recipient lookup.
	 * @param int    $user_id   WP user ID (0 for out-of-house).
	 * @return array{subscriber: array|null, modules: array}
	 */
	private function collect_pending_modules( array $statuses, bool $in_house, string $email_key, int $user_id ): array {
		$module_map = $this->notification->get_module_map();
		$subscriber = null;
		$modules    = array();

		foreach ( $statuses as $slug ) {
			$model = $module_map[ $slug ] ?? null;
			if ( ! $model instanceof Model_Notification ) {
				continue;
			}
			if ( null === $subscriber ) {
				$subscriber = $this->resolve_subscriber( $model, $in_house, $email_key, $user_id );
			}
			$modules[] = $model;
		}

		return array(
			'subscriber' => $subscriber,
			'modules'    => $modules,
		);
	}

	/**
	 * Resolve the email key used to look up a recipient in a module's recipients array.
	 *
	 * @param bool   $in_house     Whether the recipient is a WP user.
	 * @param int    $user_id      WP user ID.
	 * @param string $recipient_id Raw recipient ID (email for out-of-house).
	 * @return string
	 */
	private function resolve_email_key( bool $in_house, int $user_id, string $recipient_id ): string {
		if ( ! $in_house ) {
			return $recipient_id;
		}
		$user_data = get_userdata( $user_id );
		return $user_data ? $user_data->user_email : '';
	}

	/**
	 * Resolve a subscriber array from a notification model.
	 *
	 * @param Model_Notification $model     Notification model.
	 * @param bool               $in_house  Whether the recipient is a WP user.
	 * @param string             $email_key Email or recipient ID used as array key.
	 * @param int                $user_id   WP user ID (0 for out-of-house).
	 * @return array|null Subscriber array or null if not found.
	 */
	private function resolve_subscriber( Model_Notification $model, bool $in_house, string $email_key, int $user_id ): ?array {
		if ( $in_house ) {
			$recipient = $model->in_house_recipients[ $email_key ] ?? null;
			if ( is_array( $recipient ) ) {
				return array(
					'id'    => $user_id,
					'name'  => $recipient['name'],
					'email' => $recipient['email'],
				);
			}
			return null;
		}

		$recipient = $model->out_house_recipients[ $email_key ] ?? null;
		if ( is_array( $recipient ) ) {
			return array(
				'name'  => $recipient['name'],
				'email' => $recipient['email'],
			);
		}
		return null;
	}

	/**
	 * Send the appropriate verification email for a recipient and module list.
	 *
	 * @param array $subscriber Subscriber data array.
	 * @param array $modules    Matched notification module objects.
	 * @return array Result with success flag and response data.
	 */
	private function send_verification_email( array $subscriber, array $modules ): array {
		if ( 1 === count( $modules ) ) {
			$sent = $this->notification->send_email( $subscriber, $modules[0]->export() );
		} else {
			$sent = $this->notification->send_invite_all_email( $subscriber, $modules );
		}

		if ( $sent ) {
			return $this->response_data( true, esc_html__( 'Verification email sent.', 'defender-security' ) );
		}

		return $this->response_data( false, esc_html__( 'Could not send verification email, please try again.', 'defender-security' ) );
	}

	/**
	 * Build an empty confirmation result.
	 *
	 * @return array
	 */
	private function empty_confirmation_result(): array {
		return array(
			'found_module'      => false,
			'processed'         => false,
			'redirect_slug'     => '',
			'confirmed_modules' => array(),
			'confirmed_email'   => '',
			'confirmed_name'    => '',
		);
	}

	/**
	 * Find and confirm the matching recipient within a recipients group.
	 *
	 * @param array  $recipients Recipients array.
	 * @param string $hash       Subscription hash to match.
	 * @param string $group      Recipient group property.
	 * @return array|null Array with keys 'recipients', 'email', 'name', or null.
	 */
	private function confirm_recipients_in_group( array $recipients, string $hash, string $group ): ?array {
		foreach ( $recipients as &$recipient ) {
			if ( Model_Notification::USER_SUBSCRIBED === $recipient['status'] ) {
				continue;
			}
			$email = $recipient['email'];
			if ( ! hash_equals( $hash, hash( 'sha256', $email . AUTH_SALT ) ) ) {
				continue;
			}

			if ( 'in_house_recipients' === $group && ( ! is_user_logged_in() || $email !== $this->get_current_user_email() ) ) {
				wp_die( esc_html__( 'Invalid request.', 'defender-security' ) );
			}

			$name                = $recipient['name'];
			$recipient['status'] = Model_Notification::USER_SUBSCRIBED;

			return array(
				'recipients' => $recipients,
				'email'      => $email,
				'name'       => $name,
			);
		}

		return null;
	}
}
