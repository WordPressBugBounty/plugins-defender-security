<?php
/**
 * Handles setup wizard.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Event;
use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Component\Feature_Modal;
use WP_Defender\Controller\Data_Tracking;
use WP_Defender\Controller\Security_Tweaks;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Component\Security_Tweaks\Security_Key;

/**
 * Handles setup wizard.
 */
class Setup_Wizard extends Event {
	/**
	 * Legacy site option key for skipped setup wizard bubble state.
	 *
	 * @var string
	 */
	public const RESUME_NOTICE_OPTION = 'wd_setup_wizard_resume_notice';

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	public $slug = 'wdf-setup-wizard';

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 */
	public function __construct() {
		$this->register_routes();
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		return array_merge(
			array(
				'custom_nonce'   => wp_create_nonce( 'wpdef_setup_wizard' ),
				// Saved wizard selections, so the wizard can resume from server state after a refresh.
				'onboardingData' => get_site_option( 'wd_onboarding_data', array() ),
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Deletes any legacy resume setup wizard bubble state.
	 *
	 * @return void
	 */
	private static function clear_resume_notice_option(): void {
		delete_site_option( self::RESUME_NOTICE_OPTION );
	}

	/**
	 * Persist a single wizard step's selection to the database.
	 *
	 * Each step is merged into the canonical `wd_onboarding_data` site option so the
	 * wizard can resume from server state after a refresh or on another device. The
	 * actual module side effects are still applied atomically in finish_setup_wizard().
	 *
	 * @param  Request $request  The request object containing the step data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_step( Request $request ): Response {
		if ( ! $this->check_permission() ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid', 'defender-security' ),
				)
			);
		}

		$payload = $request->get_data();
		$step    = isset( $payload['step'] ) ? sanitize_text_field( $payload['step'] ) : '';
		$data    = isset( $payload['data'] ) && is_array( $payload['data'] ) ? $payload['data'] : array();

		$allowed_steps = array( 'local-firewall', 'hardening', 'audit-logging' );
		if ( ! in_array( $step, $allowed_steps, true ) ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid step.', 'defender-security' ),
				)
			);
		}

		$saved = get_site_option( 'wd_onboarding_data', array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}

		switch ( $step ) {
			case 'local-firewall':
				$saved['local_firewall'] = ! empty( $data['local_firewall'] );
				break;
			case 'hardening':
				$hardening          = isset( $data['hardening'] ) && is_array( $data['hardening'] )
					? $data['hardening']
					: array();
				$saved['hardening'] = array_map(
					static function ( $value ) {
						return filter_var( $value, FILTER_VALIDATE_BOOLEAN );
					},
					$hardening
				);
				break;
		}

		$saved['current_screen'] = $step;
		update_site_option( 'wd_onboarding_data', $saved );

		return new Response(
			true,
			array(
				'message' => esc_html__( 'Step saved.', 'defender-security' ),
			)
		);
	}

	/**
	 * Finish the setup wizard.
	 *
	 * @param  Request $request  The request object containing the data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function finish_setup_wizard( Request $request ): Response {
		if ( ! $this->check_permission() ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid', 'defender-security' ),
				)
			);
		}

		// Merge any per-step selections already saved with the final payload (request wins).
		$saved                 = get_site_option( 'wd_onboarding_data', array() );
		$saved                 = is_array( $saved ) ? $saved : array();
		$settings              = array_merge( $saved, $request->get_data() );
		$settings['last_scan'] = time();
		update_site_option( 'wd_onboarding_data', $settings );

		$firewall_state = (bool) $settings['local_firewall'];
		if ( $firewall_state ) {
			wd_di()->get( \WP_Defender\Controller\Firewall::class )->preset_firewall( true );
		}

		if ( isset( $settings['hardening'] ) && is_array( $settings['hardening'] ) ) {
			$toggle_to_slug  = array(
				'disable_xmlrpc'               => 'disable-xml-rpc',
				'hide_error_reporting'         => 'hide-error',
				'update_security_keys'         => 'security-key',
				'prevent_enum_users'           => 'prevent-enum-users',
				'disable_trackbacks_pingbacks' => 'disable-trackback',
				'disable_file_editor'          => 'disable-file-editor',
			);
			$hardening_state = $settings['hardening'];
			$resolved_slugs  = array();

			foreach ( $toggle_to_slug as $toggle_key => $slug ) {
				if ( ! array_key_exists( $toggle_key, $hardening_state ) ) {
					continue;
				}

				if ( filter_var( $hardening_state[ $toggle_key ], FILTER_VALIDATE_BOOLEAN ) ) {
					$resolved_slugs[] = $slug;
				}
			}

			$security_key_slug  = 'security-key';
			$auto_regen_enabled = in_array( $security_key_slug, $resolved_slugs, true );

			// Only save the autogenerate flag — don't resolve the tweak (that would regenerate keys immediately).
			$resolved_slugs = array_values( array_filter( $resolved_slugs, fn( $s ) => $s !== $security_key_slug ) );

			$security_key = wd_di()->get( Security_Key::class );
			$security_key->set_is_autogenrate_keys( $auto_regen_enabled );
			if ( $auto_regen_enabled ) {
				$security_key->cron_schedule();
			} else {
				$security_key->cron_unschedule();
			}

			// Activate all other selected hardening tweaks.
			if ( ! empty( $resolved_slugs ) ) {
				$security_tweaks = wd_di()->get( Security_Tweaks::class );
				$security_tweaks->security_tweaks_auto_action( $resolved_slugs, 'resolve' );
			}
		}

		update_site_option( 'wp_defender_shown_activator', true );
		delete_site_option( 'wp_defender_is_free_activated' );
		self::clear_resume_notice_option();
		// Skip Welcome modal.
		Feature_Modal::delete_modal_key();

		return new Response(
			true,
			array(
				'message' => esc_html__( 'Setup wizard completed successfully.', 'defender-security' ),
			)
		);
	}


	/**
	 * Close setup wizard session.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function skip(): Response {
		if ( ! $this->check_permission() ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid', 'defender-security' ),
				)
			);
		}

		update_site_option( 'wp_defender_shown_activator', true );
		delete_site_option( 'wp_defender_is_free_activated' );
		delete_site_option( 'wp_defender_onboarding_step' );
		self::clear_resume_notice_option();
		Data_Tracking::delete_modal_key();
		// Skip Welcome modal.
		Feature_Modal::delete_modal_key();

		return new Response(
			true,
			array(
				'message' => esc_html__( 'Setup wizard skipped successfully.', 'defender-security' ),
			)
		);
	}

	/**
	 * Clears skip state so the setup wizard can be opened again.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function resume_setup_wizard(): Response {
		if ( ! $this->check_permission() ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid', 'defender-security' ),
				)
			);
		}

		self::clear_resume_notice_option();
		delete_site_option( 'wp_defender_shown_activator' );
		delete_site_option( 'wp_defender_onboarding_step' );

		return new Response(
			true,
			array(
				'message' => esc_html__( 'Setup wizard resume state cleared successfully.', 'defender-security' ),
			)
		);
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
	 * Import the data of other source into this, it can be when HUB trigger the import, or user apply a preset.
	 *
	 * @param  array $data  Data from other source.
	 *
	 * @return null|void
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Remove all settings, configs generated in this container runtime.
	 *
	 * @return void
	 */
	public function remove_settings() {
		delete_site_option( 'wd_onboarding_data' );
		self::clear_resume_notice_option();
	}

	/**
	 * Remove all data.
	 *
	 * @return void
	 */
	public function remove_data() {
	}

	/**
	 * Export strings.
	 *
	 * @return array
	 */
	public function export_strings(): array {
		return array();
	}
}
