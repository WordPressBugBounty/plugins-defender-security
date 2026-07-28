<?php
/**
 * Handles notification operations.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use Exception;
use WP_Defender\Event;
use Calotes\Helper\HTTP;
use WP_Defender\Traits\User;
use Calotes\Component\Request;
use WP_Defender\Traits\Formats;
use Calotes\Component\Response;
use WP_Defender\Component\Network_Cron_Manager;
use WP_Defender\Model\Notification\Audit_Report;
use WP_Defender\Model\Notification\Malware_Report;
use WP_Defender\Model\Notification\Tweak_Reminder;
use WP_Defender\Model\Notification\Firewall_Report;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Model\Notification as Model_Notification;

/**
 * Methods for handling notifications.
 */
class Notification extends Event {

	use User;
	use Formats;

	/**
	 * Slug identifier for subscribe page.
	 *
	 * @var string
	 */
	public const SLUG_SUBSCRIBE = 'defender_listen_user_subscribe';

	/**
	 * Slug identifier for unsubscribe page.
	 *
	 * @var string
	 */
	public const SLUG_UNSUBSCRIBE = 'defender_listen_user_unsubscribe';
	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	public $slug = 'wdf-notification';

	/**
	 * Service for handling logic.
	 *
	 * @var \WP_Defender\Component\Notification
	 */
	protected $service;

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 */
	public function __construct() {
		$this->register_routes();
		$this->service = wd_di()->get( \WP_Defender\Component\Notification::class );
		add_action( 'defender_enqueue_assets', array( $this, 'enqueue_assets' ) );
		// We use custom ajax endpoint here as the nonce would fail with other user.
		add_action( 'wp_ajax_' . self::SLUG_UNSUBSCRIBE, array( $this, 'unsubscribe_and_send_email' ) );
		add_action( 'wp_ajax_nopriv_' . self::SLUG_UNSUBSCRIBE, array( $this, 'unsubscribe_and_send_email' ) );
		add_action( 'defender_notify', array( $this, 'send_notify' ), 10, 2 );
		add_action( 'admin_notices', array( $this, 'show_actions_with_subscription' ) );
		add_action( 'wp_footer', array( $this, 'show_public_subscription_notice' ) );
	}

	/**
	 * For users who have subscribed or unsubscribed confirmation.
	 *
	 * @return void
	 */
	public function show_actions_with_subscription() {
		if ( ! defined( 'IS_PROFILE_PAGE' ) || false === constant( 'IS_PROFILE_PAGE' ) ) {
			return;
		}
		$slug = defender_get_data_from_request( 'slug', 'g' );
		if ( ! is_string( $slug ) || '' === trim( $slug ) ) {
			return;
		}
		$m = $this->service->find_module_by_slug( $slug );
		if ( ! is_object( $m ) ) {
			return;
		}
		$context = defender_get_data_from_request( 'context', 'g' );
		if ( 'subscribed' === $context ) {
			$unsubscribe_link = $this->service->create_unsubscribe_url( $m->slug, $this->get_current_user_email() );
		}

		$strings = $this->get_subscription_notice_message( $m, $context, $unsubscribe_link ?? '' );
		if ( '' === $strings ) {
			return;
		}
		?>
		<div class="notice notice-success" style="position:relative;">
			<p><?php echo wp_kses_post( $strings ); ?></p>
			<a href="<?php echo esc_url_raw( get_edit_profile_url() ); ?>" class="notice-dismiss"
				style="text-decoration: none">
				<span class="screen-reader-text"><?php esc_attr_e( 'Dismiss this notice.', 'defender-security' ); ?></span>
			</a>
		</div>
		<?php
	}

	/**
	 * Show public confirmation notice for out-of-house recipients.
	 *
	 * @return void
	 */
	public function show_public_subscription_notice(): void {
		$context = defender_get_data_from_request( 'defender_subscription', 'g' );
		if ( 'confirmed' !== $context && 'unsubscribe' !== $context ) {
			return;
		}

		$slug = defender_get_data_from_request( 'slug', 'g' );
		$hash = defender_get_data_from_request( 'hash', 'g' );
		if ( ! is_string( $slug ) || '' === trim( $slug ) ) {
			return;
		}
		if ( 'confirmed' === $context && ( ! is_string( $hash ) || '' === trim( $hash ) ) ) {
			return;
		}

		$m = $this->service->find_module_by_slug( sanitize_key( $slug ) );
		if ( ! is_object( $m ) ) {
			return;
		}

		$unsubscribe_link = '';
		if ( 'confirmed' === $context ) {
			$unsubscribe_link = add_query_arg(
				array(
					'action' => self::SLUG_UNSUBSCRIBE,
					'hash'   => sanitize_text_field( $hash ),
					'slug'   => $m->slug,
				),
				admin_url( 'admin-ajax.php' )
			);
		}

		$message = $this->get_subscription_notice_message(
			$m,
			'confirmed' === $context ? 'subscribed' : 'unsubscribe',
			$unsubscribe_link
		);
		if ( '' === $message ) {
			return;
		}
		?>
		<div class="wpdef-public-subscription-notice" style="position:fixed;right:20px;bottom:20px;z-index:99999;max-width:420px;padding:14px 18px;border-left:4px solid #00a32a;background:#fff;box-shadow:0 2px 12px rgba(0,0,0,.18);font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1d2327;">
			<?php echo wp_kses_post( $message ); ?>
		</div>
		<?php
	}

	/**
	 * Build subscription notice message.
	 *
	 * @param object $module           Notification module.
	 * @param string $context          Notice context.
	 * @param string $unsubscribe_link Unsubscribe URL.
	 * @return string
	 */
	private function get_subscription_notice_message( object $module, string $context, string $unsubscribe_link = '' ): string {
		if ( 'subscribed' === $context ) {
			if ( '' === trim( $unsubscribe_link ) ) {
				return '';
			}

			return sprintf(
				/* translators: 1. Module title. 2. Unsubscribe link. */
				esc_html__(
					'You are now subscribed to receive %1$s. Made a mistake? %2$s',
					'defender-security'
				),
				'<strong>' . esc_html( $module->title ) . '</strong>',
				'<a href="' . esc_url( $unsubscribe_link ) . '" style="text-decoration: none">' . esc_html__( 'Unsubscribe', 'defender-security' ) . '</a>'
			);
		}

		if ( 'unsubscribe' === $context ) {
			return sprintf(
				/* translators: %s: Module title. */
				esc_html__( 'You are now unsubscribed from %s.', 'defender-security' ),
				'<strong>' . esc_html( $module->title ) . '</strong>'
			);
		}

		return '';
	}

	/**
	 * Renders the main view for this page.
	 */
	public function main_view() {
		$this->render( 'main' );
	}

	/**
	 * Dispatch notification.
	 *
	 * @param  string $slug  Module slug to identify the notification handler.
	 * @param  object $args  The arguments to pass to the notification.
	 */
	public function send_notify( $slug, $args ) {
		$this->service->dispatch_notification( $slug, $args );
	}

	/**
	 * Validates an email address provided in the request data.
	 *
	 * @param  Request $request  The request object .The request object containing the data to validate.
	 *
	 * @return Response The response object indicating the validation result.
	 * @defender_route
	 */
	public function validate_email( Request $request ): Response {
		$data  = $request->get_data(
			array(
				'email' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		$email = $data['email'] ?? false;
		if ( filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
			return new Response(
				true,
				array(
					'error'  => false,
					'avatar' => get_avatar_url( $data['email'] ),
				)
			);
		} else {
			return new Response( false, array( 'error' => esc_html__( 'Invalid email address.', 'defender-security' ) ) );
		}
	}

	/**
	 * Updates a WordPress user profile for an in-house recipient.
	 *
	 * @param  Request $request  The request object.
	 *
	 * @return Response The response object.
	 * @defender_route
	 */
	public function update_user_profile( Request $request ): Response {
		$data = $request->get_data(
			array(
				'id'           => array(
					'type'     => 'int',
					'sanitize' => 'sanitize_text_field',
				),
				'first_name'   => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'last_name'    => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'display_name' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);

		$user_id      = absint( $data['id'] ?? 0 );
		$display_name = trim( (string) ( $data['display_name'] ?? '' ) );

		if ( 0 === $user_id || '' === $display_name ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid user data.', 'defender-security' ) ) );
		}

		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return new Response( false, array( 'message' => esc_html__( 'You are not allowed to edit this user.', 'defender-security' ) ) );
		}

		if ( ! get_user_by( 'id', $user_id ) ) {
			return new Response( false, array( 'message' => esc_html__( 'User not found.', 'defender-security' ) ) );
		}

		$result = wp_update_user(
			array(
				'ID'           => $user_id,
				'first_name'   => trim( (string) ( $data['first_name'] ?? '' ) ),
				'last_name'    => trim( (string) ( $data['last_name'] ?? '' ) ),
				'display_name' => $display_name,
			)
		);

		if ( is_wp_error( $result ) ) {
			return new Response( false, array( 'message' => $result->get_error_message() ) );
		}

		return new Response(
			true,
			array(
				'id'           => $user_id,
				'first_name'   => trim( (string) ( $data['first_name'] ?? '' ) ),
				'last_name'    => trim( (string) ( $data['last_name'] ?? '' ) ),
				'display_name' => $display_name,
			)
		);
	}

	/**
	 * Unsubscribe process.
	 */
	public function unsubscribe_and_send_email() {
		$slug = HTTP::get( 'slug', '' );
		$hash = HTTP::get( 'hash', '' );
		$slug = sanitize_text_field( $slug );
		if ( ! is_string( $slug ) || '' === trim( $slug ) || ! is_string( $hash ) || '' === trim( $hash ) ) {
			wp_die( esc_html__( 'You shall not pass.', 'defender-security' ) );
		}
		$m = $this->service->find_module_by_slug( $slug );
		if ( ! is_object( $m ) ) {
			wp_die( esc_html__( 'You shall not pass.', 'defender-security' ) );
		}
		$inhouse   = false;
		$processed = false;
		foreach ( $m->in_house_recipients as &$recipient ) {
			$email = $recipient['email'];
			if ( hash_equals( $hash, hash( 'sha256', $email . AUTH_SALT ) ) ) {
				// We skip even an un-logged user, because the admin can change the user's access without notice.
				if ( is_user_logged_in() ) {
					if ( $email !== $this->get_current_user_email() ) {
						wp_die( esc_html__( 'Invalid request.', 'defender-security' ) );
					}
					$inhouse = true;
				}
				$recipient['status'] = Model_Notification::USER_SUBSCRIBE_CANCELED;
				$m->save();
				$processed = true;
				// Send email.
				$this->service->send_unsubscribe_email( $m, $email, $inhouse, $recipient['name'] );
				break;
			}
		}

		if ( false === $inhouse ) {
			// No match on in-house, check the outhouse list.
			foreach ( $m->out_house_recipients as &$recipient ) {
				$email = $recipient['email'];
				if ( hash_equals( $hash, hash( 'sha256', $email . AUTH_SALT ) ) ) {
					$recipient['status'] = Model_Notification::USER_SUBSCRIBE_CANCELED;
					$m->save();
					$processed = true;
					$this->service->send_unsubscribe_email( $m, $email, $inhouse, $recipient['name'] );
				}
			}
		}
		if ( $inhouse ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'slug'    => $slug,
						'context' => 'unsubscribe',
					),
					get_edit_profile_url()
				)
			);
		} elseif ( $processed ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'defender_subscription' => 'unsubscribe',
						'slug'                  => $slug,
					),
					get_home_url()
				)
			);
		} else {
			wp_safe_redirect( get_home_url() );
		}
		exit;
	}

	/**
	 * An endpoint for saving single config from frontend.
	 *
	 * @param  Request $request  The request object .The request object containing the data to save.
	 *
	 * @defender_route
	 * @return Response
	 * @throws Exception Emits Exception in case of an error.
	 */
	public function save( Request $request ): Response {
		$raw_data = $request->get_data();
		if ( ! isset( $raw_data['slug'] ) || ! is_string( $raw_data['slug'] ) || '' === trim( $raw_data['slug'] ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid data.', 'defender-security' ) ) );
		}
		$slug  = sanitize_textarea_field( $raw_data['slug'] );
		$model = $this->service->find_module_by_slug( $slug );

		if ( ! is_object( $model ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid data.', 'defender-security' ) ) );
		}
		$data = $request->get_data_by_model( $model );
		// Check config-values.
		$data['configs'] = $model->type_casting( $data['configs'] );

		$model->import( $data );
		// Ensure the model is activated. The save route is called when the user explicitly
		// saves settings, so the notification must be active after saving. If the imported
		// data already carries an active status this is a no-op; otherwise we activate it.
		if ( \WP_Defender\Model\Notification::STATUS_ACTIVE !== $model->status ) {
			$model->status = \WP_Defender\Model\Notification::STATUS_ACTIVE;
		}
		if ( $model->validate() ) {
			if ( 0 === $model->last_sent ) {
				// This means that the notification or report never sent, we will use the moment that it get activate.
				$model->last_sent = time();
			}
			$model->save();
			$this->service->send_subscription_confirm_email( $model );
			Config_Hub_Helper::set_clear_active_flag();
			// Track.
			if ( $this->is_tracking_active() ) {
				$track_data = array( 'Notification type' => $raw_data['title'] );
				// For reports. Separated check for 'Security Recommendations - Notification'.
				if ( 'report' === $raw_data['type'] ) {
					$track_data['Notification schedule'] = ucfirst( $data['frequency'] );
				} elseif ( 'tweak-reminder' === $raw_data['slug'] ) {
					$track_data['Notification schedule'] = ucfirst( $data['configs']['reminder'] );
				}
				$this->track_feature( 'def_notification_activated', $track_data );
			}

			return new Response(
				true,
				array_merge(
					array(
						'message' => esc_html__(
							'You have activated the notification successfully. Note, recipients will need to confirm their subscriptions to begin receiving notifications.',
							'defender-security'
						),
					),
					$this->data_frontend()
				)
			);
		}

		return new Response( false, array( 'message' => $model->get_formatted_errors() ) );
	}

	/**
	 * Bulk update and save changes.
	 *
	 * @param  Request $request  The request object.
	 *
	 * @defender_route
	 * @return Response
	 */
	public function save_bulk( Request $request ): Response {
		$data = $request->get_data(
			array(
				'items' => array(
					'type'     => 'array',
					'sanitize' => 'sanitize_textarea_field',
				),
			)
		);
		$this->save_items( $data['items'] );
		Config_Hub_Helper::set_clear_active_flag();

		return new Response(
			true,
			array_merge(
				$this->data_frontend(),
				array(
					'message' => esc_html__(
						'Your settings have been updated successfully. Any new recipients will receive an email to confirm their subscription.',
						'defender-security'
					),
				)
			)
		);
	}

	/**
	 * Sync the shared reports schedule to notification models that persist their own next-run timestamp.
	 *
	 * @param  Request $request  The request object.
	 *
	 * @defender_route
	 * @return Response
	 */
	public function sync_report_schedule( Request $request ): Response {
		$data = $request->get_data(
			array(
				'frequency' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'day'       => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'day_n'     => array(
					'type'     => 'int',
					'sanitize' => 'sanitize_text_field',
				),
				'time'      => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);

		$report_classes = array(
			Firewall_Report::class,
			Audit_Report::class,
			Malware_Report::class,
			Tweak_Reminder::class,
		);

		foreach ( $report_classes as $report_class ) {
			$model            = wd_di()->get( $report_class );
			$model->frequency = $data['frequency'];
			$model->day       = $data['day'];
			$model->day_n     = (int) $data['day_n'];
			$model->time      = $data['time'];

			$model->save();
		}

		Config_Hub_Helper::set_clear_active_flag();

		return new Response( true, $this->data_frontend() );
	}

	/**
	 * Process bulk saving of reports or notifications.
	 *
	 * @param  array $data       Data to save.
	 *
	 * @throws Exception Emits Exception in case of an error.
	 */
	private function save_items( array $data ): void {
		$in_house_recipients  = $data['in_house_recipients'] ?? array();
		$out_house_recipients = $data['out_house_recipients'] ?? array();

		foreach ( $data as $datum ) {
			if ( ! is_array( $datum ) || ! isset( $datum['slug'] ) ) {
				continue;
			}

			$slug  = $datum['slug'];
			$model = $this->service->find_module_by_slug( $slug );
			if ( ! is_object( $model ) ) {
				continue;
			}

			$import = array(
				'status'               => $model->status,
				'configs'              => $model->type_casting( $datum ),
				'in_house_recipients'  => $datum['in_house_recipients'] ?? $in_house_recipients,
				'out_house_recipients' => $datum['out_house_recipients'] ?? $out_house_recipients,
			);
			// since 2.7.0.
			if ( isset( $datum['is_report'] ) && (bool) $datum['is_report'] && Malware_Report::SLUG !== $slug ) {
				$import['frequency'] = $datum['frequency'] ?? $model->frequency;
				$import['day_n']     = (int) ( $datum['day_n'] ?? $model->day_n );
				$import['day']       = $datum['day'] ?? $model->day;
				$import['time']      = $datum['time'] ?? $model->time;
			}
			foreach ( $import['out_house_recipients'] as $key => $val ) {
				if ( ! filter_var( $val['email'], FILTER_VALIDATE_EMAIL ) ) {
					unset( $import['out_house_recipients'][ $key ] );
				}
			}
			$prev_in_house_emails  = array_column( $model->in_house_recipients, null, 'email' );
			$prev_out_house_emails = array_column( $model->out_house_recipients, null, 'email' );

			$model->import( $import );
			if ( $model->validate() ) {
				if ( 0 === $model->last_sent ) {
					$model->last_sent = time();
				}
				$model->save();

				$new_in_house_emails  = array_column( $import['in_house_recipients'], 'email' );
				$new_out_house_emails = array_column( $import['out_house_recipients'], 'email' );
				foreach ( $prev_in_house_emails as $email => $recipient ) {
					if ( ! in_array( $email, $new_in_house_emails, true ) ) {
						$this->service->send_unsubscribe_email( $model, $email, true, $recipient['name'] ?? '' );
					}
				}
				foreach ( $prev_out_house_emails as $email => $recipient ) {
					if ( ! in_array( $email, $new_out_house_emails, true ) ) {
						$this->service->send_unsubscribe_email( $model, $email, false, $recipient['name'] ?? '' );
					}
				}
				// Track.
				if ( $this->is_tracking_active() ) {
					$track_data = array( 'Notification type' => $model->title );
					if ( isset( $datum['is_report'] ) && (bool) $datum['is_report'] ) {
						$track_data['Notification schedule'] = 'tweak-reminder' === $slug
							? ucfirst( $datum['reminder'] ?? '' )
							: ucfirst( $datum['frequency'] ?? '' );
					}
					$this->track_feature( 'def_notification_activated', $track_data );
				}
			}
		}
	}

	/**
	 * Bulk activate.
	 *
	 * @param  Request $request  The request object.
	 *
	 * @defender_route
	 * @return Response
	 * @throws Exception Emits Exception in case of an error.
	 */
	public function bulk_activate( Request $request ): Response {
		$data  = $request->get_data(
			array(
				'slugs' => array(
					'type'     => 'array',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		$slugs = $data['slugs'];
		if ( ! is_array( $slugs ) || array() === $slugs ) {
			return new Response( false, array() );
		}

		foreach ( $slugs as $slug ) {
			$model = $this->service->find_module_by_slug( $slug );
			if ( is_object( $model ) ) {
				$model->status = Model_Notification::STATUS_ACTIVE;
				if ( 0 === $model->last_sent ) {
					// This means that the notification or report never sent, we will use the moment that it get activate.
					$model->last_sent = time();
				}
				$model->save();
			}
		}

		return new Response(
			true,
			array_merge(
				array(
					'message' => 'You have activated the notification successfully. Note, recipients will need to confirm their subscriptions to begin receiving notifications.',
				),
				$this->data_frontend()
			)
		);
	}

	/**
	 * Bulk deactivate.
	 *
	 * @param  Request $request  The request object.
	 *
	 * @defender_route
	 * @return Response
	 */
	public function bulk_deactivate( Request $request ): Response {
		$data  = $request->get_data(
			array(
				'slugs' => array(
					'type'     => 'array',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		$slugs = $data['slugs'];
		if ( ! is_array( $slugs ) || array() === $slugs ) {
			return new Response( false, array() );
		}

		foreach ( $slugs as $slug ) {
			$model = $this->service->find_module_by_slug( $slug );
			if ( is_object( $model ) ) {
				$model->status = Model_Notification::STATUS_DISABLED;
				$model->save();
			}
		}

		return new Response(
			true,
			array_merge(
				array( 'message' => esc_html__( 'You have deactivated the notifications successfully.', 'defender-security' ) ),
				$this->data_frontend()
			)
		);
	}

	/**
	 * Disable a notification module.
	 *
	 * @param  Request $request  The request object .The request object containing the data to disable the module.
	 *
	 * @defender_route
	 * @return Response The response object indicating the success or failure of the operation.
	 */
	public function disable( Request $request ): Response {
		$data = $request->get_data(
			array(
				'slug' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);

		$slug  = $data['slug'];
		$model = $this->service->find_module_by_slug( $slug );
		if ( ! is_object( $model ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid data.', 'defender-security' ) ) );
		}

		$model->status = Model_Notification::STATUS_DISABLED;
		$model->save();

		return new Response(
			true,
			array_merge(
				$this->data_frontend(),
				array(
					'message' => esc_html__( 'You have deactivated the notification successfully.', 'defender-security' ),
				)
			)
		);
	}

	/**
	 * Enqueues scripts and styles for this page.
	 * Only enqueues assets if the page is active.
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}
		// todo: add changes when the design is ready.
	}

	/**
	 * An endpoint for fetching users pool.
	 *
	 * @param  Request $request  The request object .Request data.
	 *
	 * @defender_route
	 */
	public function get_users( Request $request ) {
		$data     = $request->get_data(
			array(
				'paged'            => array(
					'type'     => 'int',
					'sanitize' => 'sanitize_text_field',
				),
				'search'           => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'exclude'          => array(
					'type' => 'array',
				),
				'module'           => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'user_role_filter' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'user_sort'        => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		$paged    = 1;
		$exclude  = $data['exclude'] ?? array();
		$username = $data['search'] ?? '';
		$slug     = $data['module'] ?? null;
		$role     = '';

		if (
			isset( $data['user_role_filter'] ) &&
			'all' !== $data['user_role_filter']
		) {
			$role = $data['user_role_filter'];
		}

		$order_by = 'ID';
		$order    = 'DESC';
		if ( isset( $data['user_sort'] ) ) {
			switch ( $data['user_sort'] ) {
				case 'recent':
					$order_by = 'registered';
					$order    = 'DESC';
					break;
				case 'alpha_asc':
					$order_by = 'display_name';
					$order    = 'ASC';
					break;
				case 'alpha_desc':
				default:
					$order_by = 'display_name';
					$order    = 'DESC';
					break;
			}
		}

		if ( strlen( $username ) ) {
			$username = "*$username*";
		}

		$users = $this->service->get_users_pool(
			$exclude,
			$role,
			$username,
			$order_by,
			$order,
			10,
			$paged
		);

		if ( ! is_null( $slug ) ) {
			$notification = $this->service->find_module_by_slug( $slug );
			if ( is_object( $notification ) ) {
				foreach ( $notification->in_house_recipients as $recipient ) {
					foreach ( $users as &$user ) {
						if ( $user['email'] === $recipient['email'] ) {
							$user['status'] = $recipient['status'];
						}
					}
				}
			}
		}

		wp_send_json_success( $users );
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings() {
		foreach ( $this->service->get_modules_as_objects() as $module ) {
			$module->delete();
		}
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
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
	 * Todo: add changes when the design is ready.
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		return array_merge(
			array(
				'alert_model'   => $this->service->get_alert_model(),
				'reports_model' => $this->service->get_reports_model(),
				'active_count'  => $this->service->count_active(),
				'hub_connector' => wd_di()->get( Hub_Connector::class )->data_frontend(),
				'antibot'       => wd_di()->get( Antibot_Global_Firewall::class )->data_frontend(),
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Imports data into the model.
	 *
	 * @param  array $data  Data to be imported into the model.
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Exports strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		$modules = wd_di()->get( self::class )->service->get_modules_as_objects();
		$strings = array();
		foreach ( $modules as $module ) {
			/* translators: %s - module title, %s - module status */
			$string = esc_html__( '%1$s: %2$s', 'defender-security' );
			if ( 'notification' === $module->type ) {
				$string = sprintf(
					$string,
					$module->title,
					Model_Notification::STATUS_ACTIVE === $module->status ? esc_html__(
						'Enabled',
						'defender-security'
					) : esc_html__( 'Disabled', 'defender-security' )
				);
			} else {
				$string = sprintf(
					$string,
					$module->title,
					Model_Notification::STATUS_ACTIVE === $module->status ? $module->to_string() : esc_html__(
						'Disabled',
						'defender-security'
					)
				);
			}
			$strings[] = $string;
		}

		return $strings;
	}

	/**
	 * Resend invite email.
	 *
	 * @param  Request $request  The request object.
	 *
	 * @defender_route
	 * @return Response
	 */
	public function resend_invite_email( Request $request ): Response {
		$data = $request->get_data(
			array(
				'slug'  => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_textarea_field',
				),
				'email' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'id'    => array(
					'type' => 'integer',
				),
				'name'  => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);

		$model = $this->service->find_module_by_slug( $data['slug'] );

		if ( ! is_object( $model ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Module not found.', 'defender-security' ) ) );
		}

		$subscriber = array(
			'email' => $data['email'],
			'name'  => $data['name'],
		);

		if ( isset( $data['id'] ) && is_int( $data['id'] ) && 0 < $data['id'] ) {
			$subscriber['id'] = $data['id'];
		}
		// Resend invite email now.
		$sent = $this->service->send_email( $subscriber, $model->export() );

		if ( $sent ) {
			return new Response( true, array( 'message' => esc_html__( 'Invitation sent successfully.', 'defender-security' ) ) );
		}

		return new Response(
			false,
			array(
				'message' => esc_html__( 'Sorry! We could not send the invitation, Please try again later.', 'defender-security' ),
			)
		);
	}

	/**
	 * Get user roles with count.
	 *
	 * @defender_route
	 */
	public function get_user_roles() {
		$user_roles = $this->service->get_user_roles();

		wp_send_json_success( $user_roles );
	}

	/**
	 * Sends a single invite email listing all notification modules the recipient was added to.
	 *
	 * @param  Request $request  Request with 'email' and 'name'.
	 * @defender_route
	 * @return Response
	 */
	public function send_invite_all_email( Request $request ): Response {
		$data       = $request->get_data(
			array(
				'email' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_email',
				),
				'name'  => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'id'    => array( 'type' => 'integer' ),
			)
		);
		$email      = $data['email'] ?? '';
		$name       = $data['name'] ?? '';
		$subscriber = array(
			'email' => $email,
			'name'  => $name,
		);
		if ( isset( $data['id'] ) && is_int( $data['id'] ) && 0 < $data['id'] ) {
			$subscriber['id'] = $data['id'];
		}
		$active_slugs = array_column( $this->service->get_modules(), 'slug' );
		$modules      = array_values(
			array_filter(
				$this->service->get_modules_as_objects(),
				static function ( $module ) use ( $active_slugs ) {
					return in_array( $module->slug, $active_slugs, true );
				}
			)
		);
		$sent         = $this->service->send_invite_all_email( $subscriber, $modules );

		return new Response( $sent, array() );
	}
}
