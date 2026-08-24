<?php
/**
 * Manages recipient subscriptions across notification modules.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Model\Notification as Model_Notification;

/**
 * Handles recipient persistence for notification modules.
 */
class Recipients extends Component {

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
	 * Save recipient subscriptions.
	 *
	 * @param array $statuses     Notification slugs to subscribe to.
	 * @param array $subscriber   Subscriber data.
	 * @param array $unsubscribed Notification slugs to unsubscribe from.
	 * @return void
	 */
	public function upsert_recipient_to_modules( array $statuses, array $subscriber, array $unsubscribed = array() ): void {
		$name       = $subscriber['name'];
		$email      = $subscriber['email'];
		$in_house   = isset( $subscriber['id'] );
		$user_id    = $in_house ? (int) $subscriber['id'] : 0;
		$user       = $in_house ? get_userdata( $user_id ) : false;
		$key        = $in_house && $user ? $user->user_email : $email;
		$module_map = $this->notification->get_module_map();

		$saved_models = $this->upsert_subscribed_modules(
			$statuses,
			$subscriber,
			$key,
			$name,
			$in_house,
			$user_id,
			$module_map
		);
		$this->unsubscribe_recipient_from_modules( $unsubscribed, $key, $in_house, $module_map );

		if ( array() !== $saved_models ) {
			if ( 1 === count( $saved_models ) ) {
				$this->notification->send_email( $subscriber, $saved_models[0]->export() );
			} else {
				$this->notification->send_invite_all_email( $subscriber, $saved_models );
			}
		}
	}

	/**
	 * Add or reactivate a recipient in selected modules.
	 *
	 * @param array  $statuses   Notification slugs to subscribe to.
	 * @param array  $subscriber Subscriber data.
	 * @param string $key        Recipient lookup key.
	 * @param string $name       Recipient display name.
	 * @param bool   $in_house   Whether the recipient is a WordPress user.
	 * @param int    $user_id    WordPress user ID for in-house recipients.
	 * @param array  $module_map Pre-built slug → model index.
	 * @return array Saved notification models.
	 */
	private function upsert_subscribed_modules(
		array $statuses,
		array $subscriber,
		string $key,
		string $name,
		bool $in_house,
		int $user_id,
		array $module_map
	): array {
		$saved_models = array();

		foreach ( $statuses as $slug ) {
			$model = $module_map[ sanitize_key( $slug ) ] ?? null;
			if ( ! $model instanceof Model_Notification ) {
				continue;
			}

			$changed = $this->upsert_recipient_to_module(
				$model,
				$subscriber,
				$key,
				$name,
				$in_house,
				$user_id
			);

			if ( ! $changed ) {
				continue;
			}

			$model->save();
			$saved_models[] = $model;
		}

		return $saved_models;
	}

	/**
	 * Add or reactivate a recipient in one module.
	 *
	 * @param Model_Notification $model      Notification model.
	 * @param array              $subscriber Subscriber data.
	 * @param string             $key        Recipient lookup key.
	 * @param string             $name       Recipient display name.
	 * @param bool               $in_house   Whether the recipient is a WordPress user.
	 * @param int                $user_id    WordPress user ID for in-house recipients.
	 * @return bool Whether the recipient data changed.
	 */
	private function upsert_recipient_to_module(
		Model_Notification $model,
		array $subscriber,
		string $key,
		string $name,
		bool $in_house,
		int $user_id
	): bool {
		if ( $in_house && 0 === $user_id ) {
			return false;
		}

		$exists = $in_house
			? isset( $model->in_house_recipients[ $key ] )
			: isset( $model->out_house_recipients[ $key ] );

		if ( $exists ) {
			$changed = $this->update_existing_recipient( $model, $in_house, $key, $name );
			if ( $in_house ) {
				$this->maybe_update_wp_user_profile( $user_id, $name, $subscriber );
			}

			return $changed;
		}

		if ( $in_house ) {
			$list                       = $model->in_house_recipients;
			$list[ $key ]               = array(
				'id'     => $user_id,
				'name'   => $name,
				'email'  => $key,
				'status' => Model_Notification::USER_SUBSCRIBE_NA,
			);
			$model->in_house_recipients = $list;
		} else {
			$list                        = $model->out_house_recipients;
			$list[ $key ]                = array(
				'name'   => $name,
				'email'  => $key,
				'status' => Model_Notification::USER_SUBSCRIBE_NA,
			);
			$model->out_house_recipients = $list;
		}

		return true;
	}

	/**
	 * Update an existing recipient record in one module.
	 *
	 * @param Model_Notification $model    Notification model.
	 * @param bool               $in_house Whether the recipient is a WordPress user.
	 * @param string             $key      Recipient lookup key.
	 * @param string             $name     Recipient display name.
	 * @return bool Whether the recipient data changed.
	 */
	private function update_existing_recipient( Model_Notification $model, bool $in_house, string $key, string $name ): bool {
		$changed    = false;
		$recipients = $in_house ? $model->in_house_recipients : $model->out_house_recipients;

		if ( $recipients[ $key ]['name'] !== $name ) {
			$recipients[ $key ]['name'] = $name;
			$changed                    = true;
		}

		if ( Model_Notification::USER_SUBSCRIBE_CANCELED === $recipients[ $key ]['status'] ) {
			$recipients[ $key ]['status'] = Model_Notification::USER_SUBSCRIBE_NA;
			$changed                      = true;
		}

		if ( $changed ) {
			if ( $in_house ) {
				$model->in_house_recipients = $recipients;
			} else {
				$model->out_house_recipients = $recipients;
			}
		}

		return $changed;
	}

	/**
	 * Mark a recipient as unsubscribed in selected modules.
	 *
	 * @param array  $unsubscribed Notification slugs to unsubscribe from.
	 * @param string $key          Recipient lookup key.
	 * @param bool   $in_house     Whether the recipient is a WordPress user.
	 * @param array  $module_map   Pre-built slug → model index.
	 * @return void
	 */
	private function unsubscribe_recipient_from_modules( array $unsubscribed, string $key, bool $in_house, array $module_map ): void {
		foreach ( $unsubscribed as $slug ) {
			$model = $module_map[ sanitize_key( $slug ) ] ?? null;
			if ( ! $model instanceof Model_Notification ) {
				continue;
			}

			$recipient = $in_house
				? ( $model->in_house_recipients[ $key ] ?? null )
				: ( $model->out_house_recipients[ $key ] ?? null );

			if (
				! is_array( $recipient )
				|| Model_Notification::USER_SUBSCRIBE_CANCELED === $recipient['status']
			) {
				continue;
			}

			if ( $in_house ) {
				$model->in_house_recipients[ $key ]['status'] = Model_Notification::USER_SUBSCRIBE_CANCELED;
			} else {
				$model->out_house_recipients[ $key ]['status'] = Model_Notification::USER_SUBSCRIBE_CANCELED;
			}
			$model->save();
			$this->notification->send_unsubscribe_email( $model, $recipient['email'], $in_house, $recipient['name'] );
		}
	}

	/**
	 * Update a WordPress user profile.
	 *
	 * @param int    $user_id      WordPress user ID.
	 * @param string $display_name User display name.
	 * @param array  $subscriber   Subscriber data.
	 * @return void
	 */
	private function maybe_update_wp_user_profile( int $user_id, string $display_name, array $subscriber ): void {
		if ( 0 === $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		$first_name = $subscriber['first_name'] ?? null;
		$last_name  = $subscriber['last_name'] ?? null;

		if ( null === $first_name && null === $last_name && '' === $display_name ) {
			return;
		}

		$args = array( 'ID' => $user_id );
		if ( '' !== $display_name ) {
			$args['display_name'] = $display_name;
		}
		if ( null !== $first_name ) {
			$args['first_name'] = $first_name;
		}
		if ( null !== $last_name ) {
			$args['last_name'] = $last_name;
		}

		wp_update_user( $args );
	}
}
