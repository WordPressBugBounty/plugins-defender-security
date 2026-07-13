<?php
/**
 * Abstract base for the Notification component.
 *
 * Contains all shared functionality used by both the pro and free versions.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use Exception;
use WP_User_Query;
use WP_Defender\Component;
use WP_Defender\Traits\IO;
use WP_Defender\Traits\User;
use WP_Defender\Model\Setting\Scan as Scan_Settings;
use WP_Defender\Model\Notification\Audit_Report;
use WP_Defender\Model\Notification\Malware_Report;
use WP_Defender\Model\Notification\Tweak_Reminder;
use WP_Defender\Model\Notification\Firewall_Report;
use WP_Defender\Model\Notification\Malware_Notification;
use WP_Defender\Model\Notification\Firewall_Notification;
use WP_Defender\Controller\Notification as Controller_Notification;

/**
 * Abstract base for the Notification component.
 */
abstract class Notification_Base extends Component {

	use User;
	use IO;

	/**
	 * Scan settings model.
	 *
	 * @var Scan_Settings
	 */
	public $scan_settings;

	/**
	 * Retrieves a pool of users based on specified criteria.
	 *
	 * @param  array  $exclude  User IDs to exclude.
	 * @param  string $role  Role to filter users by.
	 * @param  string $username  Search term for username.
	 * @param  string $order_by  Property to sort by.
	 * @param  string $order  Sort order (ASC or DESC).
	 * @param  int    $limit  Number of users to retrieve.
	 * @param  int    $paged  Page number for pagination.
	 *
	 * @return array Array of user data including display name, email, role, avatar, and ID.
	 */
	public function get_users_pool(
		$exclude = array(),
		$role = '',
		$username = '',
		$order_by = 'ID',
		$order = 'ASC',
		$limit = 15,
		$paged = 1
	): array {
		$params = array(
			'site_id' => 0,
			'role'    => $role,
			'orderby' => $order_by,
			'order'   => $order,
			'number'  => $limit,
			'paged'   => $paged,
			'exclude' => $exclude,
		);

		if ( '' !== $username ) {
			$params['search']         = strtolower( $username );
			$params['search_columns'] = array(
				'user_login',
				'user_email',
				'user_nicename',
				'display_name',
			);
		}
		$user_query = new WP_User_Query( $params );

		$pools = array();
		foreach ( $user_query->get_results() as $user ) {
			$pools[] = array(
				'name'   => $this->get_user_display( $user ),
				'email'  => $this->get_current_user_email( $user ),
				'role'   => $this->get_current_user_role( $user ),
				'avatar' => get_avatar_url( $this->get_current_user_email( $user ) ),
				'id'     => $user->ID,
				'status' => \WP_Defender\Model\Notification::USER_SUBSCRIBE_NA,
			);
		}

		return $pools;
	}

	/**
	 * Dispatches notifications based on the module slug and additional arguments.
	 *
	 * @param  string $slug  Module slug to identify the notification handler.
	 * @param  object $args  Additional arguments for the notification.
	 */
	public function dispatch_notification( $slug, $args ) {
		if ( ! is_object( $args ) ) {
			return;
		}
		$module = $this->find_module_by_slug( $slug );
		if ( is_object( $module ) ) {
			if ( 'malware-notification' === $module->slug ) {
				// For a manual scan, always notify the triggering user regardless of notification status.
				$is_manual_with_user = ! $args->is_automation && get_transient( 'defender_scan_triggered_by_' . $args->id );
				if ( $is_manual_with_user || $module->check_options() ) {
					$module->send( $args );
				}
			} elseif ( 'firewall-notification' === $module->slug && $module->check_options( $args ) ) {
				$module->send( $args );
			}
		}
	}

	/**
	 * Finds a notification module by its slug.
	 *
	 * @param  string $slug  The slug of the module.
	 *
	 * @return mixed Returns the module object if found.
	 */
	public function find_module_by_slug( $slug ) {
		switch ( $slug ) {
			case Tweak_Reminder::SLUG:
				return wd_di()->get( Tweak_Reminder::class );
			case Malware_Notification::SLUG:
				return wd_di()->get( Malware_Notification::class );
			case Firewall_Notification::SLUG:
				return wd_di()->get( Firewall_Notification::class );
			case Malware_Report::SLUG:
				return wd_di()->get( Malware_Report::class );
			case Firewall_Report::SLUG:
				return wd_di()->get( Firewall_Report::class );
			case Audit_Report::SLUG:
				return wd_di()->get( Audit_Report::class );
			default:
				return false;
		}
	}

	/**
	 * Send a verification email to users.
	 *
	 * @param  \WP_Defender\Model\Notification $model  Notification model containing recipient details.
	 *
	 * @throws Exception Emits Exception in case of an error.
	 */
	public function send_subscription_confirm_email( \WP_Defender\Model\Notification $model ) {
		foreach ( $model->in_house_recipients as &$subscriber ) {
			if ( ! isset( $subscriber['status'] ) || '' === $subscriber['status'] ) {
				continue;
			}
			if ( \WP_Defender\Model\Notification::USER_SUBSCRIBE_NA !== $subscriber['status'] ) {
				continue;
			}
			$ret = $this->send_email( $subscriber, $model->export() );

			if ( $ret ) {
				$subscriber['status'] = \WP_Defender\Model\Notification::USER_SUBSCRIBE_WAITING;
			}
		}
		foreach ( $model->out_house_recipients as &$subscriber ) {
			if ( ! isset( $subscriber['status'] ) || '' === $subscriber['status'] ) {
				continue;
			}
			if ( \WP_Defender\Model\Notification::USER_SUBSCRIBE_NA !== $subscriber['status'] ) {
				continue;
			}
			$ret = $this->send_email( $subscriber, $model->export() );

			if ( $ret ) {
				$subscriber['status'] = \WP_Defender\Model\Notification::USER_SUBSCRIBE_WAITING;
			}
		}

		$model->save();
	}

	/**
	 * Sends an email to a subscriber.
	 *
	 * @param  array $subscriber  Subscriber information.
	 * @param  array $data  Notification slug, title, type.
	 *
	 * @return bool Returns true if the email was sent successfully.
	 */
	public function send_email( $subscriber, $data ) {
		$headers = wd_di()->get( Mail::class )->get_headers(
			defender_noreply_email( 'wd_confirm_noreply_email' ),
			'subscription'
		);
		$email   = $subscriber['email'];
		$name    = $subscriber['name'] ?? '';
		$inhouse = false;
		if ( isset( $subscriber['id'] ) ) {
			$inhouse = true;
		}
		$url          = $this->create_subscribe_url( $data['slug'], $email, $inhouse );
		$subject      = sprintf( /* translators: %s: Model title. */ 'Subscribe to %s', $data['title'] );
		$notification = wd_di()->get( Controller_Notification::class );
		$content_body = $notification->render_partial(
			'email/confirm',
			array(
				'subject'           => $subject,
				'email'             => $email,
				'notification_name' => $data['title'],
				'url'               => $url,
				'site_url'          => network_site_url(),
				'name'              => $name,
			),
			false
		);
		$content      = $notification->render_partial(
			'email/index',
			array(
				'title'            => $data['title'],
				'content_body'     => $content_body,
				'unsubscribe_link' => '',
			),
			false
		);

		return wp_mail( $email, $subject, $content, $headers );
	}

	/**
	 * Sends a single invite email listing all notification modules the recipient was added to.
	 *
	 * @param  array $subscriber  Subscriber info with 'email', 'name', and optionally 'id' for in-house.
	 * @param  array $modules     Array of notification model objects.
	 *
	 * @return bool True if the email was sent successfully.
	 */
	public function send_invite_all_email( array $subscriber, array $modules ): bool {
		$email   = $subscriber['email'];
		$name    = $subscriber['name'] ?? '';
		$inhouse = isset( $subscriber['id'] );

		$module_list = array();
		$slugs       = array();
		foreach ( $modules as $module ) {
			$module_list[] = array( 'title' => $module->title );
			$slugs[]       = $module->slug;
		}

		if ( array() === $module_list ) {
			return false;
		}

		$url          = $this->create_subscribe_all_url( $slugs, $email, $inhouse );
		$headers      = wd_di()->get( Mail::class )->get_headers(
			defender_noreply_email( 'wd_confirm_noreply_email' ),
			'subscription'
		);
		$subject      = esc_html__( 'Confirm your subscriptions', 'defender-security' );
		$notification = wd_di()->get( Controller_Notification::class );
		$content_body = $notification->render_partial(
			'email/confirm-all',
			array(
				'name'     => $name,
				'email'    => $email,
				'site_url' => network_site_url(),
				'modules'  => $module_list,
				'url'      => $url,
			),
			false
		);
		$content      = $notification->render_partial(
			'email/index',
			array(
				'title'            => esc_html__( 'Confirm your subscriptions', 'defender-security' ),
				'content_body'     => $content_body,
				'unsubscribe_link' => '',
			),
			false
		);

		return wp_mail( $email, $subject, $content, $headers );
	}

	/**
	 * Sends a subscription confirmation email to a user.
	 *
	 * @param  string $email  Email address of the subscriber.
	 * @param  object $m  Notification model object.
	 * @param  string $name  Name of the subscriber.
	 */
	public function send_subscribed_email( $email, $m, $name ) {
		$headers      = wd_di()->get( Mail::class )->get_headers(
			defender_noreply_email( 'wd_subscribe_noreply_email' ),
			'subscribe_confimed'
		);
		$notification = wd_di()->get( Controller_Notification::class );
		$subject      = esc_html__( 'Confirmed', 'defender-security' );
		$content_body = $notification->render_partial(
			'email/subscribed',
			array(
				'subject'           => esc_html__( 'Subscription Confirmed', 'defender-security' ),
				'notification_name' => $m->title,
				'url'               => $this->create_unsubscribe_url( $m->slug, $email ),
				'name'              => $name,
			)
		);
		$content      = $notification->render_partial(
			'email/index',
			array(
				'title'            => preg_replace( '/ - (Notification|Alert)$/', '', $m->title ),
				'content_body'     => $content_body,
				'unsubscribe_link' => '',
			),
			false
		);

		wp_mail( $email, $subject, $content, $headers );
	}

	/**
	 * Sends a single subscription confirmation email for multiple modules.
	 *
	 * @param  string $email  Email address of the subscriber.
	 * @param  array  $modules  Array of notification model objects.
	 * @param  string $name  Name of the subscriber.
	 */
	public function send_subscribed_all_email( $email, array $modules, $name ) {
		$module_list = array();
		foreach ( $modules as $module ) {
			$module_list[] = array(
				'title' => $module->title,
				'url'   => $this->create_unsubscribe_url( $module->slug, $email ),
			);
		}

		if ( array() === $module_list ) {
			return;
		}

		$headers      = wd_di()->get( Mail::class )->get_headers(
			defender_noreply_email( 'wd_subscribe_noreply_email' ),
			'subscribe_confimed'
		);
		$notification = wd_di()->get( Controller_Notification::class );
		$subject      = esc_html__( 'Confirmed', 'defender-security' );
		$content_body = $notification->render_partial(
			'email/subscribed-all',
			array(
				'subject' => esc_html__( 'Subscriptions Confirmed', 'defender-security' ),
				'modules' => $module_list,
				'name'    => $name,
			),
			false
		);
		$content      = $notification->render_partial(
			'email/index',
			array(
				'title'            => esc_html__( 'Subscriptions Confirmed', 'defender-security' ),
				'content_body'     => $content_body,
				'unsubscribe_link' => '',
			),
			false
		);

		wp_mail( $email, $subject, $content, $headers );
	}

	/**
	 * Sends an unsubscribe email to a user.
	 *
	 * @param  object $m  Notification model object.
	 * @param  string $email  Email address of the subscriber.
	 * @param  bool   $inhouse  Indicates if the user is an in-house user.
	 * @param  string $name  Name of the subscriber.
	 */
	public function send_unsubscribe_email( $m, $email, $inhouse, $name ) {
		$subject      = esc_html__( 'Unsubscribed', 'defender-security' );
		$url          = $this->create_subscribe_url( $m->slug, $email, $inhouse );
		$notification = wd_di()->get( Controller_Notification::class );
		$content_body = $notification->render_partial(
			'email/unsubscribe',
			array(
				'subject'           => esc_html__( 'Unsubscribed', 'defender-security' ),
				'notification_name' => $m->title,
				'url'               => $url,
				'name'              => $name,
			),
			false
		);
		$title        = preg_replace( '/ - (Notification|Alert)$/', '', $m->title );
		$title        = preg_replace( '/ - Reporting$/', '', $title );
		$content      = $notification->render_partial(
			'email/index',
			array(
				'title'            => $title,
				'content_body'     => $content_body,
				'unsubscribe_link' => '',
			),
			false
		);
		$headers      = wd_di()->get( Mail::class )->get_headers(
			defender_noreply_email( 'wd_unsubscribe_noreply_email' ),
			'unsubscription'
		);

		wp_mail( $email, $subject, $content, $headers );
	}

	/**
	 * Create a URL for unsubscribing from notifications.
	 *
	 * @param  string $slug  Notification slug.
	 * @param  string $email  Email address of the subscriber.
	 *
	 * @return string Unsubscribe URL.
	 */
	public function create_unsubscribe_url( $slug, $email ): string {
		return add_query_arg(
			array(
				'action' => Controller_Notification::SLUG_UNSUBSCRIBE,
				'hash'   => hash( 'sha256', $email . AUTH_SALT ),
				'slug'   => $slug,
			),
			admin_url( 'admin-ajax.php' )
		);
	}

	/**
	 * Create a URL for subscribing to notifications.
	 *
	 * @param  string $slug  Notification slug.
	 * @param  string $email  Email address of the subscriber.
	 * @param  bool   $inhouse  Indicates if the user is an in-house user.
	 *
	 * @return string Subscribe URL.
	 */
	public function create_subscribe_url( $slug, $email, $inhouse ): string {
		return add_query_arg(
			array(
				'action'  => Controller_Notification::SLUG_SUBSCRIBE,
				'hash'    => hash( 'sha256', $email . AUTH_SALT ),
				'uid'     => $slug,
				'inhouse' => $inhouse,
			),
			admin_url( 'admin-ajax.php' )
		);
	}

	/**
	 * Create a URL for subscribing to multiple notifications.
	 *
	 * @param  array  $slugs  Notification slugs.
	 * @param  string $email  Email address of the subscriber.
	 * @param  bool   $inhouse  Indicates if the user is an in-house user.
	 *
	 * @return string Subscribe URL.
	 */
	public function create_subscribe_all_url( array $slugs, $email, $inhouse ): string {
		return add_query_arg(
			array(
				'action'  => Controller_Notification::SLUG_SUBSCRIBE,
				'hash'    => hash( 'sha256', $email . AUTH_SALT ),
				'uids'    => implode( ',', array_map( 'sanitize_key', $slugs ) ),
				'inhouse' => $inhouse,
			),
			admin_url( 'admin-ajax.php' )
		);
	}

	/**
	 * Counts the number of active modules.
	 *
	 * @return int Number of active modules.
	 */
	public function count_active(): int {
		$count = 0;
		foreach ( $this->get_modules() as $module ) {
			if ( \WP_Defender\Model\Notification::STATUS_ACTIVE === $module['status'] ) {
				++$count;
			}
		}

		return $count;
	}

	/**
	 * Get available user roles with user count.
	 *
	 * @return array Return user roles with user count.
	 */
	public function get_user_roles(): array {
		$user_roles = count_users();

		if ( isset( $user_roles['avail_roles'] ) ) {
			foreach ( $user_roles['avail_roles'] as $key => $value ) {
				if ( 0 === $value ) {
					unset( $user_roles['avail_roles'][ $key ] );
				}
			}
		}

		return $user_roles;
	}

	/**
	 * Get all modules as array of arrays.
	 *
	 * @return array
	 */
	abstract public function get_modules(): array;

	/**
	 * Get all modules as array of objects.
	 *
	 * @return array
	 */
	abstract public function get_modules_as_objects(): array;

	/**
	 * Return the time that the next report will be triggered.
	 *
	 * @return string|null
	 */
	abstract public function get_next_run();

	/**
	 * Get inactive modules.
	 *
	 * @return array
	 */
	abstract public function get_inactive_modules(): array;

	/**
	 * Get active pro report modules as arrays.
	 *
	 * @return array
	 */
	abstract public function get_active_pro_reports(): array;

	/**
	 * Get active pro report modules as objects.
	 *
	 * @return array
	 */
	abstract public function get_active_pro_reports_as_objects(): array;

	/**
	 * Dispatches reports if conditions are met.
	 */
	abstract public function maybe_dispatch_report();
}
