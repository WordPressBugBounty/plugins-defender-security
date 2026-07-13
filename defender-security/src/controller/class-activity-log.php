<?php
/**
 * The activity logs class.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Controller;

/**
 * Activites log.
 *
 * Class Activity_Log
 */
class Activity_Log extends Controller {
	/**
	 * Notification data key.
	 *
	 * @var string
	 */
	private static $notification_data_key = 'wp_defender_notifications';

	/**
	 * Maximum number of notifications.
	 *
	 * @var int
	 */
	private static $max_notification = 50;

	/**
	 * Registers routes.
	 */
	public function __construct() {
		$this->register_routes();
	}

	/**
	 * Remove settings.
	 */
	public function remove_settings() {
		delete_site_option( self::$notification_data_key );
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
	}

	/**
	 * Get data for frontend.
	 *
	 * @return array
	 */
	public function data_frontend(): array {
		return array_merge(
			array(
				'notifications' => $this->get_notifications_for_ui(),
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Export to array.
	 *
	 * @return array
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Import data.
	 *
	 * @param array $data The data to import.
	 */
	public function import_data( $data ) {}

	/**
	 * Export strings
	 *
	 * @return array
	 */
	public function export_strings() {
		return array();
	}

	/**
	 * Record a notification atomically.
	 *
	 * Uses a single JSON_ARRAY_APPEND database query so concurrent background
	 * processes never overwrite each other's entries.
	 *
	 * @param mixed $notification Notification data.
	 *
	 * @return bool True if the notification was successfully stored, false otherwise.
	 */
	public function record_log( $notification ) {
		$sanitized_notification = $this->sanitize_notification( $notification );
		if ( empty( $sanitized_notification ) ) {
			return false;
		}

		$notifications   = $this->get_notifications();
		$notifications[] = $sanitized_notification;

		$result = update_site_option(
			self::$notification_data_key,
			$notifications
		);

		return false !== $result;
	}

	/**
	 * Add a notification from the UI.
	 *
	 * @param Request $request The request object containing filter parameters.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function add_notification( Request $request ): Response {
		$data = $request->get_data(
			array(
				'notification' => array(
					'type'     => 'array',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);

		if ( ! is_array( $data['notification'] ) ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid notification data.', 'defender-security' ),
				)
			);
		}

		$success = $this->record_log( $data['notification'] );

		if ( ! $success ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Failed to save notification.', 'defender-security' ),
				)
			);
		}

		return new Response(
			true,
			array(
				'notifications' => $this->get_notifications_for_ui(),
			)
		);
	}

	/**
	 * Get the notifications.
	 *
	 * Reads directly from the database (bypasses object cache) to ensure
	 * writes from other background processes are visible.
	 *
	 * @return array
	 */
	public function get_notifications(): array {
		$notifications = get_site_option( self::$notification_data_key, array() );

		return is_array( $notifications ) ? $notifications : array();
	}

	/**
	 * Sanitize a notification.
	 *
	 * @param mixed $notification Notification data.
	 *
	 * @return array{id: string, timestamp: string|int, type: string, content: string, url: string}
	 */
	private function sanitize_notification( $notification ) {
		if ( empty( $notification['content'] ) ) {
			return array();
		}
		// Sanitize and ensure all expected fields exist.
		$sanitized              = array();
		$sanitized['id']        = isset( $notification['id'] ) ? sanitize_text_field( $notification['id'] ) : uniqid( 'defender_notification_' );
		$sanitized['timestamp'] = isset( $notification['timestamp'] ) ? sanitize_text_field( $notification['timestamp'] ) : microtime( true );
		$sanitized['type']      = isset( $notification['type'] ) ? sanitize_text_field( $notification['type'] ) : 'info';
		$sanitized['module']    = isset( $notification['module'] ) ? sanitize_text_field( $notification['module'] ) : '';
		$sanitized['content']   = isset( $notification['content'] ) ? sanitize_text_field( $notification['content'] ) : '';
		$sanitized['url']       = isset( $notification['url'] ) ? sanitize_text_field( $notification['url'] ) : '';

		return $sanitized;
	}

	/**
	 * Sanitize a notification for display in the UI.
	 * Translates the notification content.
	 *
	 * @param array $notification Notification data.
	 *
	 * @return array Sanitized notification data.
	 */
	private function sanitize_notification_for_ui( $notification ) {
		$sanitized = $this->sanitize_notification( $notification );
		if ( empty( $sanitized['content'] ) ) {
			return array();
		}

		return $sanitized;
	}

	/**
	 * Get notifications.
	 *
	 * @return array
	 */
	private function get_notifications_for_ui(): array {
		$notifications = $this->get_notifications();

		if ( empty( $notifications ) ) {
			$this->record_log(
				array(
					'module'  => 'defender',
					'content' => esc_html__( 'Welcome to Defender', 'defender-security' ),
				)
			);
			$notifications = $this->get_notifications();
		} else {
			$notifications = $this->get_limited_notifications( $notifications );
		}

		return array_map( array( $this, 'sanitize_notification_for_ui' ), $notifications );
	}

	/**
	 * Fetch the latest notifications for the UI.
	 * Called after a long-running background process completes or dies on-page,
	 * so the frontend can replace optimistic entries with server-written ones.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function fetch_notifications(): Response {
		return new Response(
			true,
			array(
				'notifications' => $this->get_notifications_for_ui(),
			)
		);
	}

	/**
	 * Get the stored list to the maximum allowed size, keeping the most recent entries.
	 *
	 * @param array $notifications Notification data.
	 *
	 * @return array
	 */
	private function get_limited_notifications( array $notifications ): array {
		// Keep only valid notification entries (arrays with expected keys).
		$notifications = array_values( array_filter( $notifications, 'is_array' ) );

		if ( count( $notifications ) <= self::$max_notification ) {
			return $notifications;
		}

		// Sort newest-first, then keep only the allowed maximum.
		usort(
			$notifications,
			function ( $a, $b ) {
				return ( $b['timestamp'] ?? 0 ) <=> ( $a['timestamp'] ?? 0 );
			}
		);

		return array_slice( $notifications, 0, self::$max_notification );
	}
}
