<?php
/**
 * Handles interactions with SmartCrawl SEO.
 *
 * @package WP_Defender\Integrations
 */

namespace WP_Defender\Integrations;

if ( ! defined( 'ABSPATH' ) ) {
	die;
}

/**
 * SmartCrawl integration module.
 *
 * @since 5.8.0
 */
class Smartcrawl {

	/**
	 * Check if SmartCrawl plugin is active.
	 *
	 * @return bool True if SmartCrawl is active, false otherwise.
	 */
	public function is_activated(): bool {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return class_exists( '\SmartCrawl\Modules\Advanced\Robots\Controller' ) ||
				function_exists( 'smartcrawl_get_robots_url' ) ||
				is_plugin_active( 'smartcrawl-seo/wpmu-dev-seo.php' );
	}

	/**
	 * Check if we should use SmartCrawl's filter instead of direct injection.
	 *
	 * SmartCrawl will serve robots.txt only when ALL conditions are met:
	 * 1. Plugin is loaded (class exists)
	 * 2. Robots.txt module is enabled in settings
	 * 3. No physical robots.txt file exists
	 * 4. Site is in root directory (not a subdirectory install)
	 *
	 * @return bool True if SmartCrawl will actually serve robots.txt, false otherwise.
	 */
	public function should_serve_robots(): bool {
		// Quick check: SmartCrawl controller class must exist.
		if ( ! class_exists( '\SmartCrawl\Modules\Advanced\Robots\Controller' ) ) {
			return false;
		}

		// Let SmartCrawl's own logic determine if it will serve robots.txt.
		// This checks: module enabled, no physical file, root directory, etc.
		$sc_controller = \SmartCrawl\Modules\Advanced\Robots\Controller::get();

		return $sc_controller->should_run();
	}

	/**
	 * Get SmartCrawl's robots.txt content.
	 *
	 * @return string The robots.txt content from SmartCrawl, or empty string if unavailable.
	 */
	public function get_robots_content(): string {
		if ( ! class_exists( '\SmartCrawl\Modules\Advanced\Robots\Controller' ) ) {
			return '';
		}

		$sc_controller = \SmartCrawl\Modules\Advanced\Robots\Controller::get();

		return $sc_controller->get_content();
	}
}
