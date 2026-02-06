<?php
/**
 * Handles defender feature activation/deactivation events for audit logging.
 *
 * @package WP_Defender\Component\Audit
 */

namespace WP_Defender\Component\Audit;

use WP_Defender\Traits\User;
use WP_Defender\Model\Audit_Log;

/**
 * Handles defender feature activation/deactivation events for audit logging.
 *
 * @since 5.8.0
 */
class Feature_Audit extends Audit_Event {

	use User;

	const CONTEXT_DEFENDER_FEATURE   = 'feature';
	const ACTION_FEATURE_DEACTIVATED = 'feature_deactivated';

	/**
	 * Return an array of hooks.
	 *
	 * @return array
	 */
	public function get_hooks(): array {
		return array(
			'update_site_option' => array(
				'args'        => array( 'option', 'value', 'old_value', 'network_id' ),
				'event_type'  => Audit_Log::EVENT_TYPE_SETTINGS,
				'context'     => self::CONTEXT_DEFENDER_FEATURE,
				'action_type' => self::ACTION_FEATURE_DEACTIVATED,
				'callback'    => array( $this, 'audit_logging' ),
			),
		);
	}

	/**
	 * Callback for audit logging when audit logging feature is deactivated.
	 *
	 * @param string $hook_name The name of the hook.
	 * @param array  $params The parameters passed to the hook.
	 *
	 * @return array|false
	 */
	public function audit_logging( string $hook_name, array $params ): bool|array {
		$option = $params['option'] ?? '';
		if ( 'wd_audit_settings' !== $option ) {
			return false;
		}

		$old_raw   = $params['old_value'] ?? null;
		$new_raw   = $params['value'] ?? null;
		$old_value = is_string( $old_raw ) ? json_decode( $old_raw, true ) : ( is_array( $old_raw ) ? $old_raw : null );
		$new_value = is_string( $new_raw ) ? json_decode( $new_raw, true ) : ( is_array( $new_raw ) ? $new_raw : null );
		$blog_name = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : '';
		$username  = $this->get_source_of_action();
		if ( is_array( $old_value ) && isset( $old_value['enabled'] ) ) {
			$old_enabled = (bool) $old_value['enabled'];
		} else {
			$old_enabled = false;
		}

		if ( is_array( $new_value ) && isset( $new_value['enabled'] ) ) {
			$new_enabled = (bool) $new_value['enabled'];
		} else {
			$new_enabled = false;
		}
		// Only log when the feature is deactivated.
		if ( $old_enabled && ! $new_enabled ) {
			return array(
				sprintf(
				/* translators: 1: Site name, 2: Username */
					esc_html__( '%1$s Audit Logging feature deactivated by %2$s', 'defender-security' ),
					$blog_name,
					$username
				),
				self::CONTEXT_DEFENDER_FEATURE,
				self::ACTION_FEATURE_DEACTIVATED,
			);
		}

		return false;
	}
}
