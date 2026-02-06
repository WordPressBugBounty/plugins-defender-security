<?php
/**
 * Handles theme events for Audit Logging.
 *
 * @package WP_Defender\Component\Audit
 */

namespace WP_Defender\Component\Audit;

use WP_Defender\Traits\User;
use WP_Defender\Model\Audit_Log;

/**
 * Handles theme related all events for Audit Logging.
 *
 * @since 5.8.0
 */
class Theme_Audit extends Audit_Event {
	use User;

	public const CONTEXT_NETWORK_THEME    = 'network_theme';
	public const ACTION_NETWORK_ACTIVATED = 'network_activated';

	/**
	 * Returns the hooks to monitor theme events.
	 *
	 * @return array
	 */
	public function get_hooks(): array {
		if ( is_multisite() ) {
			return array(
				'update_site_option_allowedthemes' => array(
					'args'        => array( 'option', 'value', 'old_value', 'network_id' ),
					'event_type'  => Audit_Log::EVENT_TYPE_SYSTEM,
					'context'     => self::CONTEXT_NETWORK_THEME,
					'action_type' => self::ACTION_NETWORK_ACTIVATED,
					'callback'    => array( $this, 'network_theme_enabled' ),
				),
			);
		}

		return array();
	}

	/**
	 * Callback for logging when a theme is activated  on network
	 *
	 * @param string $hook_name The hook name.
	 * @param array  $params Hook parameters.
	 *
	 * @return array An array containing the log text, context, and action type.
	 */
	public function network_theme_enabled( string $hook_name, array $params ): array {
		unset( $hook_name ); // Not used, but kept for parity with callback signature.

		$new_allowed = is_array( $params['value'] ) ? $params['value'] : array();
		$old_allowed = is_array( $params['old_value'] ) ? $params['old_value'] : array();
		$new_themes  = array_diff( array_keys( $new_allowed ), array_keys( $old_allowed ) );

		if ( array() === $new_themes ) {
			return array();
		}

		$theme_names = array();
		foreach ( $new_themes as $theme_slug ) {
			$theme         = wp_get_theme( $theme_slug );
			$theme_names[] = $theme && $theme->exists() ? $theme->get( 'Name' ) : $theme_slug;
		}

		$blog_name = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : '';
		$message   = sprintf(
		/* translators: 1: Blog theme, 2: Source of action (username or Hub) 3: Theme name. */
			esc_html__( '%1$s %2$s activated theme %3$s on network', 'defender-security' ),
			$blog_name,
			$this->get_source_of_action(),
			implode( ', ', $theme_names )
		);

		return array( $message, self::CONTEXT_NETWORK_THEME, self::ACTION_NETWORK_ACTIVATED );
	}
}
