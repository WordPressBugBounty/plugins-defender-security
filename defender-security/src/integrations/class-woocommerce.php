<?php
/**
 * Handles interactions with Woocommerce.
 *
 * @package WP_Defender\Integrations
 */

namespace WP_Defender\Integrations;

if ( ! defined( 'ABSPATH' ) ) {
	die;
}

/**
 * Woocommerce integration module.
 *
 * @since 2.6.1
 * @since 3.3.0 Add locations.
 */
class Woocommerce {

	public const WOO_LOGIN_FORM = 'woo_login',
		WOO_REGISTER_FORM       = 'woo_register',
		WOO_LOST_PASSWORD_FORM  = 'woo_lost_password',
		WOO_CHECKOUT_FORM       = 'woo_checkout';

	/**
	 * Check if Woo is activated.
	 *
	 * @return bool
	 */
	public function is_activated(): bool {
		return class_exists( 'woocommerce' );
	}

	/**
	 * Detects if the request is coming from a WooCommerce login context.
	 *
	 * Checks in the following order of reliability:
	 * 1. Direct WooCommerce page detection (most reliable).
	 * 2. WooCommerce endpoint detection.
	 * 3. Form submission detection (more reliable than referer).
	 * 4. AJAX detection.
	 * 5. Fallback: Referer check (least reliable).
	 *
	 * @return bool
	 */
	public function is_wc_login_context(): bool {
		if ( ! $this->is_activated() ) {
			return false;
		}

		// 1. Direct WooCommerce page detection (most reliable).
		if ( function_exists( 'is_account_page' ) && is_account_page() ) {
			return true;
		}

		// 2. WooCommerce endpoint detection.
		if ( function_exists( 'is_wc_endpoint_url' ) &&
			( is_wc_endpoint_url( 'lost-password' ) || is_wc_endpoint_url( 'customer-logout' )
		) ) {
			return true;
		}

		// 3. Form submission detection (more reliable than referer).
		$post_data = defender_get_data_from_request( null, 'p' );
		if ( isset( $post_data['woocommerce-login-nonce'] ) ||
			isset( $post_data ['woocommerce_checkout_login'] ) ||
			( isset( $post_data ['login'] ) && is_checkout() ) ||
			isset( $post_data['wc_reset_password'] ) ) {
			return true;
		}

		// 4. AJAX detection.
		if ( wp_doing_ajax() && isset( $post_data['wc-ajax'] ) ) {
			return true;
		}

		// 5. Fallback: Referer check (least reliable).
		$referer = wp_get_referer();
		if ( false !== $referer && function_exists( 'wc_get_page_id' ) ) {
			$my_account_page_id = wc_get_page_id( 'myaccount' );
			if ( $my_account_page_id > 0 ) {
				$my_account_url = get_permalink( $my_account_page_id );
				if ( $my_account_url && strpos( $referer, $my_account_url ) === 0 ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Retrieves an array of WooCommerce forms with their respective translations.
	 *
	 * @return array An associative array where the keys are the form identifiers and the values are the translated
	 *     form names.
	 */
	public static function get_forms(): array {
		return array(
			self::WOO_LOGIN_FORM         => esc_html__( 'Login', 'defender-security' ),
			self::WOO_REGISTER_FORM      => esc_html__( 'Registration', 'defender-security' ),
			self::WOO_LOST_PASSWORD_FORM => esc_html__( 'Lost Password', 'defender-security' ),
			self::WOO_CHECKOUT_FORM      => esc_html__( 'Checkout', 'defender-security' ),
		);
	}
}
