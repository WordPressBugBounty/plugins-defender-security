<?php
/**
 * The advanced tools class.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Event;
use WP_Filesystem_Base;
use Calotes\Component\Response;
use WP_Defender\Integrations\MaxMind_Geolocation;
use WP_Defender\Controller\Captcha as Captcha_Controller;
use WP_Defender\Controller\Mask_Login as Mask_Login_Controller;
use WP_Defender\Controller\Password_Reset as Password_Reset_Controller;
use WP_Defender\Controller\Strong_Password as Strong_Password_Controller;
use WP_Defender\Controller\Session_Protection as Session_Protection_Controller;
use WP_Defender\Controller\Password_Protection as Password_Protection_Controller;
use WP_Defender\Model\Setting\Session_Protection as Model_Session_Protection;

/**
 * Since advanced tools will have many submodules, this just using for render.
 *
 * Class Login_Access
 */
class Login_Access extends Event {
	/**
	 * Ajax action for page/post search.
	 */
	private const SEARCH_POSTS_AJAX_ACTION = 'wpdef_hide_login_search_posts';

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	protected $slug = 'wdf-advanced-tools';

	/**
	 * Initializes the model and service, registers routes.
	 */
	public function __construct() {
		$this->register_page(
			$this->get_title(),
			$this->slug,
			array( $this, 'main_view' ),
			$this->parent_slug
		);
		$this->register_routes();

		// Additional hooks.
		add_action( 'defender_enqueue_assets', array( $this, 'enqueue_assets' ), 11 );
		add_filter( 'admin_body_class', array( $this, 'admin_body_class' ) );
		add_action( 'wp_ajax_' . self::SEARCH_POSTS_AJAX_ACTION, array( $this, 'ajax_search_posts' ) );
	}

	/**
	 * Adds a page-specific body class to the admin area.
	 *
	 * @param string $classes Existing body classes.
	 *
	 * @return string
	 */
	public function admin_body_class( string $classes ): string {
		if ( $this->is_page_active() ) {
			return trim( $classes . ' wdf-login-access-react-page' );
		}

		return $classes;
	}

	/**
	 * Return the title of the page.
	 *
	 * @return string The title of the page.
	 */
	public function get_title(): string {
		return esc_html__( 'Login & Access', 'defender-security' );
	}

	/**
	 * Render the view page.
	 *
	 * @return void
	 */
	public function main_view(): void {
		$this->render( 'main' );
	}

	/**
	 * Save settings.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_settings(): Response {
		return new Response(
			true,
			array(
				'message'    => esc_html__( 'Your settings have been updated.', 'defender-security' ),
				'auto_close' => true,
			)
		);
	}

	/**
	 * Converts the current object to an array representation.
	 *
	 * @return array The array representation of the object.
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Enqueues scripts and styles for this page.
	 * Only enqueues assets if the page is active.
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}

		$handle = 'defender-ui-login-access';
		wp_enqueue_media();

		wp_enqueue_script(
			$handle,
			WP_DEFENDER_BASE_URL . 'assets/js/login-access-ui.js',
			array( 'def-vue', 'def-manifest', 'def-core-ui', 'defender', 'wp-i18n' ),
			DEFENDER_VERSION,
			true
		);
		wp_set_script_translations( $handle, 'wpdef' );

		wp_localize_script(
			$handle,
			'defenderUIData',
			array_merge(
				$this->get_shared_data(),
				$this->data_frontend()
			)
		);

		wp_enqueue_style(
			$handle,
			WP_DEFENDER_BASE_URL . 'assets/css/showcase.css',
			array(),
			DEFENDER_VERSION
		);

		$this->enqueue_main_assets();
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings(): void {
		( new \WP_Defender\Model\Setting\Mask_Login() )->delete();
		( new \WP_Defender\Model\Setting\Security_Headers() )->delete();
		( new \WP_Defender\Model\Setting\Password_Protection() )->delete();
		( new \WP_Defender\Model\Setting\Password_Reset() )->delete();
		( new \WP_Defender\Model\Setting\Captcha() )->delete();
		( new \WP_Defender\Model\Setting\Strong_Password() )->delete();
		( new Model_Session_Protection() )->delete();
	}

	/**
	 * Delete all the data.
	 */
	public function remove_data(): void {
		wd_di()->get( Mask_Login_Controller::class )->remove_data();
		// Remove data of all Password features.
		wd_di()->get( Password_Protection_Controller::class )->remove_data();
		wd_di()->get( Password_Reset_Controller::class )->remove_data();
		wd_di()->get( Strong_Password_Controller::class )->remove_data();
		wd_di()->get( Session_Protection_Controller::class )->remove_data();
		wd_di()->get( Captcha_Controller::class )->remove_data();

		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		$service_geo = wd_di()->get( MaxMind_Geolocation::class );
		$maxmind_dir = $service_geo->get_db_base_path();
		$wp_filesystem->delete( $maxmind_dir, true );
		$arr_deleted_files = array(
			\WP_Defender\Behavior\Scan\Malware_Scan::MALWARE_LOG,
			\WP_Defender\Controller\Firewall::FIREWALL_LOG,
			wd_internal_log(),
			\WP_Defender\Controller\Scan::SCAN_LOG,
			\WP_Defender\Component\Password_Protection::PASSWORD_LOG,
			\WP_Defender\Component\IP\Antibot_Global_Firewall::LOG_FILE_NAME,
			\WP_Defender\Component\Security_Tweak::LOG_FILE_NAME,
			// Outdated logs.
			'defender.log',
		);

		foreach ( $arr_deleted_files as $deleted_file ) {
			$wp_filesystem->delete( $deleted_file );
		}

		$this->handle_log_file_deletion();
	}

	/**
	 * Handle log file deletion.
	 *
	 * @since 4.7.2
	 * @return void
	 */
	public function handle_log_file_deletion(): void {
		if ( is_multisite() ) {
			global $wpdb;

			$offset = 0;
			$limit  = 100;
			$blogs  = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->prepare(
					"SELECT blog_id FROM {$wpdb->blogs} LIMIT %d, %d",
					$offset,
					$limit
				),
				ARRAY_A
			);
			while ( is_array( $blogs ) && array() !== $blogs ) {
				foreach ( $blogs as $blog ) {
					switch_to_blog( $blog['blog_id'] );

					$this->delete_log_files();

					restore_current_blog();
				}
				$offset += $limit;
				$blogs   = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
					$wpdb->prepare(
						"SELECT blog_id FROM {$wpdb->blogs} LIMIT %d, %d",
						$offset,
						$limit
					),
					ARRAY_A
				);
			}
		} else {
			$this->delete_log_files();
		}
	}

	/**
	 * Delete log files.
	 *
	 * @since 4.7.2
	 * @return void
	 */
	private function delete_log_files(): void {
		global $wp_filesystem;

		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		$upload_dir  = wp_upload_dir();
		$upload_path = $upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'wp-defender';

		if ( is_dir( $upload_path ) ) {
			$files = glob( $upload_path . '/*.log' );

			foreach ( $files as $file ) {
				if ( $wp_filesystem->is_file( $file ) ) {
					$wp_filesystem->delete( $file );
				}
			}
		}
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {

		return array(
			'sessionProtection' => wd_di()->get( Session_Protection_Controller::class )->data_frontend(),
			'twoFactorAuth'     => wd_di()->get( Two_Factor::class )->data_frontend(),
			'pwnedPasswords'    => wd_di()->get( Password_Protection_Controller::class )->data_frontend(),
			'strongPassword'    => wd_di()->get( Strong_Password_Controller::class )->data_frontend(),
			'passwordReset'     => wd_di()->get( Password_Reset_Controller::class )->data_frontend(),
			'maskLogin'         => wd_di()->get( Mask_Login_Controller::class )->data_frontend(),
			'botProtection'     => wd_di()->get( Captcha_Controller::class )->data_frontend(),
			'loginAccessAjax'   => array(
				'searchPostsAction' => self::SEARCH_POSTS_AJAX_ACTION,
				'searchPostsNonce'  => wp_create_nonce( self::SEARCH_POSTS_AJAX_ACTION ),
			),
			'loginAccessCopy'   => array(
				'hideLoginUrl' => array(
					'title'              => __( 'Hide Login URL', 'defender-security' ),
					'intro'              => __(
						'Change the default WordPress login URL to make it harder for bots to find, while keeping access simple for your users.',
						'defender-security'
					),
					'slugTitle'          => __( 'New login URL slug', 'defender-security' ),
					'slugTooltip'        => __(
						'Set a unique URL slug to replace your default login endpoints.',
						'defender-security'
					),
					'slugPlaceholder'    => __( 'Custom URL', 'defender-security' ),
					'slugExample'        => __( "E.g. 'my-secret-login'.", 'defender-security' ),
					'slugAvoid'          => __(
						'Avoid using: wp-admin, wp-login.php, wp-login, login, dashboard, admin.',
						'defender-security'
					),
					'slugConflictStrong' => __( 'URL already exist.', 'defender-security' ),
					'slugConflictRest'   => __( 'Please enter a different slug.', 'defender-security' ),
					'trafficTitle'       => __( 'Redirect traffic', 'defender-security' ),
					'trafficTooltip'     => __(
						'Choose where visitors should be redirected when they try to access the default WordPress login URLs.',
						'defender-security'
					),
					'options'            => array(
						'off'  => __( 'Off', 'defender-security' ),
						'page' => __( 'Page', 'defender-security' ),
						'url'  => __( 'Custom URL', 'defender-security' ),
					),
					'redirectToUrl'      => __( 'Redirect to URL', 'defender-security' ),
					'redirectUrlLabel'   => __( 'Redirection URL', 'defender-security' ),
					'redirectToPageId'   => __( 'Redirect to page/post ID', 'defender-security' ),
					'redirectUrlHelp'    => __(
						'Visitors accessing default login URLs will be redirected to the custom URL defined above. E.g 404-error',
						'defender-security'
					),
					'pageSearchLabel'    => __( 'Type post / Page title', 'defender-security' ),
					'pageSearchEmpty'    => __( 'No matching pages or posts found.', 'defender-security' ),
					'offDescription'     => __(
						'Redirect visitors and bots attempting to access default WordPress login URLs to an alternative URL, preventing 404 errors.',
						'defender-security'
					),
					'ariaClearPage'      => __( 'Clear selected page', 'defender-security' ),
					'ariaSelectPage'     => __( 'Select page', 'defender-security' ),
				),
			),
		);
	}

	/**
	 * Ajax endpoint for searching posts/pages by title.
	 *
	 * @return void
	 */
	public function ajax_search_posts(): void {
		check_ajax_referer( self::SEARCH_POSTS_AJAX_ACTION );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => esc_html__( 'Permission denied.', 'defender-security' ),
				),
				403
			);
		}

		$per_page = isset( $_POST['per_page'] ) ? absint( wp_unslash( $_POST['per_page'] ) ) : 10;
		$search   = isset( $_POST['search'] ) ? sanitize_text_field( wp_unslash( $_POST['search'] ) ) : '';
		$per_page = max( 1, min( 50, $per_page ) );

		add_filter( 'posts_where', array( $this, 'posts_where_title' ), 10, 2 );
		$post_query = new \WP_Query(
			array(
				'post_type'            => array( 'page', 'post' ),
				'posts_per_page'       => $per_page,
				'search_by_post_title' => $search,
				'post_status'          => 'publish',
				'orderby'              => 'title',
				'order'                => 'ASC',
			)
		);
		remove_filter( 'posts_where', array( $this, 'posts_where_title' ), 10 );

		$data = array();
		foreach ( $post_query->posts as $post ) {
			$data[] = array(
				'id'   => $post->ID,
				'name' => $post->post_title,
				'url'  => get_permalink( $post->ID ),
			);
		}

		wp_send_json_success( $data );
	}

	/**
	 * Filter posts query by title.
	 *
	 * @param string    $where    Existing where clause.
	 * @param \WP_Query $wp_query Query object.
	 *
	 * @return string
	 */
	public function posts_where_title( string $where, \WP_Query $wp_query ): string {
		global $wpdb;

		$search_term = $wp_query->get( 'search_by_post_title' );
		if ( is_string( $search_term ) && '' !== trim( $search_term ) ) {
			$where .= ' AND ' . $wpdb->posts . '.post_title LIKE \'%' . esc_sql( $wpdb->esc_like( $search_term ) ) . '%\'';
		}

		return $where;
	}

	/**
	 * Imports data into the model.
	 *
	 * @param array $data  Data to be imported into the model.
	 */
	public function import_data( array $data ) {}

	/**
	 * Exports strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		return array();
	}
}
