<?php
/**
 * Prevents user enumeration on a WordPress site to enhance security by blocking various endpoints and methods that can
 * be used to discover user information.
 *
 * @package WP_Defender\Component\Security_Tweaks
 */

namespace WP_Defender\Component\Security_Tweaks;

use WP_Error;
use WP_REST_Response;
use WP_Sitemaps_Provider;
use WP_Defender\Traits\Security_Tweaks_Option;

/**
 * Prevent user enumeration.
 */
class Prevent_Enum_Users extends Abstract_Security_Tweaks implements Security_Key_Const_Interface {

	use Security_Tweaks_Option;

	/**
	 * The slug identifier for this tweak.
	 *
	 * @var string
	 */
	public string $slug = 'prevent-enum-users';

	/**
	 * Status to check if the issue has been resolved.
	 *
	 * @var bool
	 */
	public $resolved = false;

	/**
	 * Enabled user enumerations list.
	 *
	 * @var array
	 */
	private $enabled_user_enums = array();

	/**
	 * Check whether the issue has been resolved or not.
	 *
	 * @return bool
	 */
	public function check(): bool {
		return $this->resolved;
	}

	/**
	 * Here is the code for processing.
	 *
	 * @return bool
	 */
	public function process(): bool {
		return true;
	}

	/**
	 * This is for un-do stuff that has been done in @process.
	 *
	 * @return bool
	 */
	public function revert(): bool {
		return true;
	}

	/**
	 * Shield up.
	 *
	 * @return void
	 */
	public function shield_up() {
		$this->resolved = true;

		if ( is_admin() || defender_is_wp_cli() ) {
			return;
		}

		add_filter( 'oembed_response_data', array( $this, 'oembed_author_filter' ), 99 );
		add_filter( 'wp_sitemaps_users_pre_url_list', array( $this, 'block_user_url_sitemap' ), 99, 0 );
		add_filter( 'wp_sitemaps_add_provider', array( $this, 'block_user_provider_sitemap' ), 99, 2 );
		add_filter( 'rest_authentication_errors', array( $this, 'block_rest_api_user_endpoint' ) );
		add_filter( 'rest_endpoints', array( $this, 'block_rest_api_user_endpoints' ), 99 );
		add_action( 'rest_api_init', array( $this, 'register_dynamic_post_type_filters' ) );

		$query = defender_get_data_from_request( 'QUERY_STRING', 's' );
		if ( ! is_string( $query ) || '' === $query ) {
			return;
		}

		$this->maybe_block( $query );

		add_filter( 'redirect_canonical', array( $this, 'maybe_block' ) );
	}

	/**
	 * Maybe block the request if it's trying to access the author page with query param.
	 *
	 * @param  string $request  Request of current page.
	 *
	 * @return string
	 */
	public function maybe_block( string $request ) {
		if ( ! current_user_can( 'edit_others_posts' ) ) {
			$params = array();
			wp_parse_str( strtolower( $request ), $params );

			if (
				isset( $params['author'] )
				&& is_scalar( $params['author'] )
				&& '' !== preg_replace( '/[^0-9,-]/', '', $params['author'] )
			) {
				wp_die(
					esc_html__( 'Sorry, you are not allowed to access this page', 'defender-security' ),
					esc_html__( 'Forbidden', 'defender-security' ),
					403
				);
			}
		}

		return $request;
	}

	/**
	 * Retrieve the tweak's label.
	 *
	 * @return string
	 */
	public function get_label(): string {
		return esc_html__( 'Prevent user enumeration', 'defender-security' );
	}

	/**
	 * Get the error reason.
	 *
	 * @return string
	 */
	public function get_error_reason(): string {
		return wp_kses(
			__( '<strong>User enumeration is currently allowed</strong> and may expose your site.', 'defender-security' ),
			array(
				'strong' => array(),
			)
		);
	}

	/**
	 * Return a summary data of this tweak.
	 *
	 * @return array
	 */
	public function to_array(): array {
		$enabled      = $this->get_enabled_user_enums();
		$stop_rest    = in_array( 'enum-rest', $enabled, true );
		$hide_user    = in_array( 'enum-oembed', $enabled, true );
		$disable_maps = in_array( 'enum-sitemap', $enabled, true );
		$all_enabled  = $stop_rest && $hide_user && $disable_maps;

		$success_reason = $all_enabled
			? wp_strip_all_tags( __( 'All recommendation settings are turned on.', 'defender-security' ) )
			: wp_strip_all_tags( __( 'Custom recommendation settings are turned on.', 'defender-security' ) );

		return array(
			'slug'             => $this->slug,
			'title'            => $this->get_label(),
			'errorReason'      => $this->get_error_reason(),
			'successReason'    => $success_reason,
			'misc'             => array(
				'show_revert_button'     => true,
				'show_action_button'     => true,
				'stop_rest_api'          => $stop_rest,
				'hide_user_id'           => $hide_user,
				'disable_author_sitemap' => $disable_maps,
			),
			'bulk_description' => wp_strip_all_tags( __( 'Author redirects can make usernames easier for bots to find. Prevent user enumeration to protect your login area and reduce brute force risk.', 'defender-security' ) ),
			'bulk_title'       => wp_strip_all_tags( __( 'Prevent user enumeration', 'defender-security' ) ),
		);
	}

	/**
	 * Getter method of enabled_user_enums.
	 *
	 * @return array Return array of enabled enumeration options.
	 */
	public function get_enabled_user_enums(): array {
		$enabled_user_enums = $this->get_option( 'enabled_user_enums' );

		$this->enabled_user_enums = is_null( $enabled_user_enums )
			? array()
			: (array) $enabled_user_enums;

		return $this->enabled_user_enums;
	}

	/**
	 * Setter method of enabled_user_enums.
	 *
	 * @param  array $value  Array of enabled user enumeration options.
	 *
	 * @return bool Return true if value updated, otherwise false.
	 */
	public function set_enabled_user_enums( $value ): bool {
		$this->enabled_user_enums = ! is_array( $value ) ? (array) $value : $value;

		return $this->update_option(
			'enabled_user_enums',
			$this->enabled_user_enums
		);
	}

	/**
	 * Filters the author detail from oEmbed response data.
	 *
	 * @param  array $data  The response data.
	 *
	 * @return array $data The response data.
	 */
	public function oembed_author_filter( $data ) {
		if (
			is_array( $data ) &&
			in_array(
				'enum-oembed',
				$this->get_enabled_user_enums(),
				true
			)
		) {
			unset( $data['author_name'], $data['author_url'] );
		}

		return $data;
	}

	/**
	 * Blocks user url generation in sitemap.
	 * Consider the URL: http://example.com/wp-sitemap-users-1.xml will not return user URL XML.
	 *
	 * @return bool|null If option sitemap enumeration enabled then return false else null/void will return.
	 */
	public function block_user_url_sitemap(): ?bool {
		if (
			in_array(
				'enum-sitemap',
				$this->get_enabled_user_enums(),
				true
			)
		) {
			return false;
		}

		return null;
	}

	/**
	 * Blocks the user provider sitemap before it is added from wp-sitemap.xml.
	 *
	 * @param  WP_Sitemaps_Provider $provider  Instance of a WP_Sitemaps_Provider.
	 * @param  string               $name  Name of the sitemap provider.
	 *
	 * @return bool|WP_Sitemaps_Provider If option sitemap enumeration enabled then return false else
	 *     WP_Sitemaps_Provider instance.
	 */
	public function block_user_provider_sitemap( $provider, string $name ) {
		if (
			'users' === $name &&
			in_array(
				'enum-sitemap',
				$this->get_enabled_user_enums(),
				true
			)
		) {
			return false;
		}

		return $provider;
	}

	/**
	 * Block user REST API endpoint for not logged-in access.
	 *
	 * @param  WP_Error|null|true $errors  WP_Error if authentication error, null if authentication
	 *                                 method wasn't used, true if authentication succeeded.
	 *
	 * @return WP_Error|null|true $errors WP_Error if authentication error, null if authentication
	 *                                    method wasn't used, true if authentication succeeded.
	 */
	public function block_rest_api_user_endpoint( $errors ) {
		$request_uri = (string) filter_input( INPUT_SERVER, 'REQUEST_URI', FILTER_SANITIZE_URL ) ?? '';
		$rest_route  = (string) filter_input( INPUT_GET, 'rest_route', FILTER_SANITIZE_URL ) ?? '';

		$is_url_match = preg_match( '/users/i', $request_uri ) !== 0 ||
						preg_match( '/users/i', $rest_route ) !== 0;

		if (
			in_array(
				'enum-rest',
				$this->get_enabled_user_enums(),
				true
			) &&
			$is_url_match &&
			! is_user_logged_in()
		) {
			return new WP_Error(
				'rest_cannot_access',
				esc_html__( 'Only logged-in users can access the User endpoint REST API.', 'defender-security' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		return $errors;
	}

	/**
	 * Block REST user endpoints for not logged-in access.
	 *
	 * @param array $endpoints The available endpoints.
	 *
	 * @return array
	 */
	public function block_rest_api_user_endpoints( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		if ( ! in_array( 'enum-rest', $this->get_enabled_user_enums(), true ) ) {
			return $endpoints;
		}

		$endpoints_to_remove = array(
			'/wp/v2/users',
			'/wp/v2/users/(?P<id>[\d]+)',
		);

		foreach ( $endpoints_to_remove as $route ) {
			if ( isset( $endpoints[ $route ] ) ) {
				unset( $endpoints[ $route ] );
			}
		}

		return $endpoints;
	}

	/**
	 * Dynamically register rest_prepare_{$post_type} filters for all REST-exposed post types.
	 *
	 * @return void
	 */
	public function register_dynamic_post_type_filters() {
		// Optimization: If REST API protection is disabled in the settings, we don't log anything at all.
		if ( ! in_array( 'enum-rest', $this->get_enabled_user_enums(), true ) ) {
			return;
		}

		$post_types = get_post_types( array( 'show_in_rest' => true ) );

		foreach ( $post_types as $post_type ) {
			add_filter( "rest_prepare_{$post_type}", array( $this, 'strip_author_link' ), 10, 1 );
		}
	}

	/**
	 * Remove the 'author' relationship link from REST API responses for not logged-in access.
	 *
	 * @param WP_REST_Response $response The response object.
	 *
	 * @return WP_REST_Response
	 */
	public function strip_author_link( $response ) {
		// This is a mandatory check because it is triggered at the moment of data transfer and knows for sure whether the user who sent the request is authorized.
		if ( ! is_user_logged_in() ) {
			$response->remove_link( 'author' );
		}

		return $response;
	}
}
