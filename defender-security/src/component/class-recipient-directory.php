<?php
/**
 * Builds recipient directory data for notification modules.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Model\Notification as Model_Notification;

/**
 * Handles recipient search and frontend directory data.
 */
class Recipient_Directory extends Component {

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
	 * Search WordPress users by name or email.
	 *
	 * @param string $search Search term.
	 * @return array User result rows.
	 */
	public function search_users( string $search ): array {
		if ( strlen( $search ) < 3 ) {
			return array();
		}

		$wp_users = get_users(
			array(
				'search'         => "*{$search}*",
				'search_columns' => array( 'user_login', 'user_email', 'display_name' ),
				'number'         => 20,
			)
		);

		$results = array();
		foreach ( $wp_users as $user ) {
			$results[] = array(
				'id'    => (string) $user->ID,
				'name'  => $user->display_name,
				'email' => $user->user_email,
				'role'  => ! empty( $user->roles ) ? $user->roles[0] : '',
			);
		}

		return $results;
	}

	/**
	 * Delete a recipient from all notification modules.
	 *
	 * @param string $recipient_id Recipient ID or out-of-house email.
	 * @return void
	 */
	public function delete_recipient( string $recipient_id ): void {
		$is_in_house = is_numeric( $recipient_id );
		$email       = '';
		if ( $is_in_house ) {
			$user_data = get_userdata( (int) $recipient_id );
			$email     = $user_data ? $user_data->user_email : '';
		}

		foreach ( $this->notification->get_modules_as_objects() as $model ) {
			$changed = false;

			if ( $is_in_house ) {
				if ( '' !== $email && isset( $model->in_house_recipients[ $email ] ) ) {
					unset( $model->in_house_recipients[ $email ] );
					$changed = true;
				}
			} elseif ( isset( $model->out_house_recipients[ $recipient_id ] ) ) {
				unset( $model->out_house_recipients[ $recipient_id ] );
				$changed = true;
			}

			if ( $changed ) {
				$model->save();
			}
		}
	}

	/**
	 * Get recipients across all modules.
	 *
	 * @return array Recipient data.
	 */
	public function get_all_recipients(): array {
		$seen       = array();
		$result     = array();
		$modules    = $this->notification->get_modules_as_objects();
		$avatar_map = $this->get_in_house_avatar_map( $modules );

		foreach ( $modules as $model ) {
			$this->collect_in_house_recipients( $result, $seen, $model, $avatar_map );
			$this->collect_out_house_recipients( $result, $seen, $model );
		}

		return array_values( $result );
	}

	/**
	 * Collect in-house recipients for one module.
	 *
	 * @param array              $result     Accumulated recipients list.
	 * @param array              $seen       Deduplication index.
	 * @param Model_Notification $model      Notification model.
	 * @param array              $avatar_map Avatar URLs keyed by email.
	 * @return void
	 */
	private function collect_in_house_recipients( array &$result, array &$seen, Model_Notification $model, array $avatar_map ): void {
		$is_module_active = Model_Notification::STATUS_ACTIVE === $model->status;
		foreach ( $model->in_house_recipients as $recipient ) {
			$key  = 'u_' . ( $recipient['id'] ?? $recipient['email'] );
			$base = array(
				'id'       => (string) ( $recipient['id'] ?? $recipient['email'] ),
				'avatar'   => $avatar_map[ $recipient['email'] ] ?? '',
				'role'     => $recipient['role'] ?? '',
				'_inHouse' => true,
			);
			$this->collect_recipient( $result, $seen, $key, $recipient, $model->slug, $base, $is_module_active );
		}
	}

	/**
	 * Collect out-of-house recipients for one module.
	 *
	 * @param array              $result Accumulated recipients list.
	 * @param array              $seen   Deduplication index.
	 * @param Model_Notification $model  Notification model.
	 * @return void
	 */
	private function collect_out_house_recipients( array &$result, array &$seen, Model_Notification $model ): void {
		$is_module_active = Model_Notification::STATUS_ACTIVE === $model->status;
		foreach ( $model->out_house_recipients as $recipient ) {
			$key  = 'o_' . $recipient['email'];
			$base = array(
				'id'       => $recipient['email'],
				'avatar'   => '',
				'role'     => '',
				'_inHouse' => false,
			);
			$this->collect_recipient( $result, $seen, $key, $recipient, $model->slug, $base, $is_module_active );
		}
	}

	/**
	 * Get avatar URLs for all in-house recipient emails.
	 *
	 * @param array $modules Notification modules.
	 * @return array
	 */
	private function get_in_house_avatar_map( array $modules ): array {
		$in_house_emails = array();
		foreach ( $modules as $model ) {
			foreach ( $model->in_house_recipients as $recipient ) {
				if ( ! empty( $recipient['email'] ) ) {
					$in_house_emails[ $recipient['email'] ] = true;
				}
			}
		}

		$avatar_map = array();
		foreach ( array_keys( $in_house_emails ) as $email ) {
			$avatar_map[ $email ] = get_avatar_url( $email );
		}

		return $avatar_map;
	}

	/**
	 * Add a recipient entry to the result or append its module slug if already seen.
	 *
	 * @param array  $result           Accumulated recipients list.
	 * @param array  $seen             Deduplication index.
	 * @param string $key              Unique recipient key.
	 * @param array  $recipient        Recipient data from the model.
	 * @param string $slug             Notification module slug.
	 * @param array  $base             Type-specific fields.
	 * @param bool   $is_module_active Whether the notification module is enabled.
	 * @return void
	 */
	private function collect_recipient( array &$result, array &$seen, string $key, array $recipient, string $slug, array $base, bool $is_module_active = true ): void {
		$status   = $recipient['status'] ?? '';
		$canceled = Model_Notification::USER_SUBSCRIBE_CANCELED === $status;
		$add_slug = $is_module_active && ! $canceled;

		if ( isset( $seen[ $key ] ) ) {
			if ( $add_slug ) {
				$result[ $seen[ $key ] ]['statuses'][] = $slug;
			}
			return;
		}

		$seen[ $key ] = count( $result );
		$result[]     = $base + array(
			'name'     => $recipient['name'],
			'email'    => $recipient['email'],
			'status'   => $status,
			'statuses' => $add_slug ? array( $slug ) : array(),
		);
	}
}
