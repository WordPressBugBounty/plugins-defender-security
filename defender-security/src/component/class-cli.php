<?php
/**
 * This file contains the Cli class which is used to handle WP-CLI commands for the WP Defender plugin.
 * It provides methods to manage scans, audits, firewall settings, and more through the command line.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_CLI;
use Countable;
use Exception;
use Throwable;
use Faker\Factory;
use WP_Filesystem_Base;
use WP_CLI\ExitException;
use WP_Defender\Traits\IO;
use WP_Defender\Traits\Theme;
use WP_Defender\Traits\Plugin;
use WP_Defender\Traits\Formats;
use WP_Defender\Model\Audit_Log;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Model\Lockout_Ip;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Controller\Dashboard;
use WP_Defender\Controller\Two_Factor;
use WP_Defender\Controller\Login_Access;
use WP_Defender\Controller\Main_Setting;
use WP_Defender\Controller\Audit_Logging;
use WP_Defender\Model\Scan as Model_Scan;
use WP_Defender\Controller\Security_Tweaks;
use WP_Defender\Model\Setting\Login_Lockout;
use WP_Defender\Behavior\Scan\Core_Integrity;
use WP_Defender\Controller\Blocklist_Monitor;
use WP_Defender\Model\Setting\Password_Reset;
use WP_Defender\Model\Setting\Notfound_Lockout;
use WP_Defender\Model\Setting\Security_Headers;
use WP_Defender\Component\Scan as Scan_Component;
use WP_Defender\Component\Logger\Rotation_Logger;
use WP_Defender\Model\Setting\User_Agent_Lockout;
use function WP_CLI\Utils\format_items;

if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class Cli
 */
class Cli {

	use Formats {
		calculate_date_interval as protected;
		format_bytes_into_readable as protected;
		format_date_time as protected;
		get_date as protected;
		get_days_of_week as protected;
		get_times as protected;
		get_timezone_string as protected;
		local_to_utc as protected;
		moment_datetime_format_from as protected;
		persistent_hub_datetime_format as protected;
		time_since as protected;
		get_local_human_date as protected;
		release_cron_lock as protected;
		create_lock as protected;
		has_lock as protected;
		remove_lock as protected;
		check_plugin_on_wp_org as protected;
		check_by_readme_file as protected;
		acquire_cron_lock as protected;
		compare_hashes as protected;
		delete_dir as protected;
		detect_line_ending as protected;
		get_abs_plugin_path_by_slug as protected;
		get_active_plugin_names as protected;
		get_path_of_themes_dir as protected;
		get_log_path as protected;
		get_plugin_details_by as protected;
		get_plugin_directory_name as protected;
		get_plugin_headers as protected;
		get_plugin_relative_path as protected;
		get_plugin_slugs as protected;
		get_plugins as protected;
		get_plugin_slug_by as protected;
		get_theme as protected;
		get_theme_slugs as protected;
		get_themes as protected;
		get_time_diff as protected;
		handle_wp_org_response_by as protected;
		is_active_plugin as protected;
		is_active_theme as protected;
		is_likely_wporg_slug as protected;
		ping_wp_org_by_plugin_slug as protected;
	}
	use IO;
	use Theme;
	use Plugin;

	/**
	 * Run scans and manage scan results via WP-CLI.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : Action to perform.
	 * ---
	 * options:
	 *   - run
	 *   - ignore
	 *   - unignore
	 *   - resolve
	 *   - delete
	 *   - clear_logs
	 * ---
	 *
	 * [--type=<type>]
	 * : Filter by issue type. Omit to target all types.
	 * ---
	 * options:
	 *   - detailed
	 *   - core_integrity
	 *   - plugin_integrity
	 *   - vulnerability
	 *   - suspicious_code
	 *   - plugin_outdated
	 *   - plugin_closed
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Run a full scan.
	 *     $ wp defender scan run
	 *     Success: All done!
	 *
	 *     # Run a detailed scan with table output.
	 *     $ wp defender scan run --type=detailed
	 *
	 *     # Ignore all active core integrity issues.
	 *     $ wp defender scan ignore --type=core_integrity
	 *
	 *     # Resolve all active vulnerability issues.
	 *     $ wp defender scan resolve --type=vulnerability
	 *
	 *     # Delete all suspicious code files.
	 *     $ wp defender scan delete --type=suspicious_code
	 *
	 *     # Clear completed scan logs.
	 *     $ wp defender scan clear_logs
	 *
	 * @param mixed $args    Command arguments.
	 * @param mixed $options Command options.
	 *
	 * @throws ExitException If an invalid command is provided.
	 */
	public function scan( $args, $options ) {
		if ( ! is_array( $args ) || array() === $args ) {
			WP_CLI::error( 'Invalid command' );

			return;
		}
		[$command] = $args;
		switch ( $command ) {
			case 'run':
				$this->scan_all( $options );
				break;
			case 'clear_logs':
				$this->scan_clear_logs();
				break;
			default:
				$commands = array( 'ignore', 'unignore', 'resolve', 'delete' );
				if ( in_array( $command, $commands, true ) ) {
					WP_CLI::confirm( 'This can cause your site get fatal error and can\'t restore back unless you have a backup, are you sure to continue?', $options );
					$this->scan_task( $command, $options );
				} else {
					WP_CLI::error( sprintf( 'Unknown command %s', $command ) );
				}
				break;
		}
	}

	/**
	 * Starts a full scan based on the provided options.
	 *
	 * @param array $options Command options.
	 */
	private function scan_all( $options ) {
		$type        = $options['type'] ?? null;
		$is_detailed = false;
		switch ( $type ) {
			case null:
				// All items.
				$type = null;
				break;
			case 'detailed':
				$is_detailed = true;
				break;
			default:
				WP_CLI::error( sprintf( 'Unknown scan type %s', $type ) );
				break;
		}
		WP_CLI::log( 'Check if there is a scan ongoing...' );
		$scan = Model_Scan::get_active();
		if ( ! is_object( $scan ) ) {
			WP_CLI::log( 'No active scan, creating...' );
			// Match the web-triggered flow: clear stale idle scans first so they don't skew "last scan" lookups.
			wd_di()->get( Model_Scan::class )->delete_idle();
			delete_site_option( Core_Integrity::ISSUE_CHECKSUMS );
			$scan = Model_Scan::create();
			if ( is_wp_error( $scan ) ) {
				WP_CLI::error( $scan->get_error_message() );
			}
			wd_di()->get( Scan_Component::class )->gather_actioned_plugin_details();
		} else {
			WP_CLI::log( 'Continue from last scan' );
		}
		// Start detailed scan.
		if ( $is_detailed ) {
			$start = microtime( true );
		}
		$handler = wd_di()->get( Scan_Component::class );
        while ( $handler->process() === false ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
		}
		$scan = Model_Scan::get_last();
		if ( ! is_object( $scan ) || is_wp_error( $scan ) ) {
			return;
		}
		$results = $scan->to_array();
		if ( is_array( $results ) && isset( $results['issues_items'] ) && array() !== $results['issues_items'] ) {
			$count = is_array( $results['issues_items'] ) || $results['issues_items'] instanceof Countable ? count( $results['issues_items'] ) : 0;
			// Finish detailed scan.
			if ( $is_detailed ) {
				format_items( 'table', $results['issues_items'], array( 'type', 'short_desc', 'full_path' ) );
				WP_CLI::log( sprintf( 'Saved %d items.', $count ) );
				$finish = microtime( true ) - $start;
				WP_CLI::log( 'Scan takes ' . round( $finish, 2 ) . 's to process.' );
			} else {
				WP_CLI::log( sprintf( 'Found %d issues.', $count ) );
			}
		}
		WP_CLI::success( 'All done!' );
	}

	/**
	 * Clear completed action scheduler logs.
	 */
	private function scan_clear_logs() {
		$scan_component = wd_di()->get( Scan_Component::class );
		$result         = $scan_component::clear_logs();
		$message        = $result['success'] ?? $result['error'] ?? 'Malware scan logs are cleared';

		WP_CLI::log( $message );
	}

	/**
	 * Executes tasks based on the type of scan.
	 *
	 * @param string $command The task to perform.
	 * @param mixed  $options Command options.
	 */
	private function scan_task( $command, $options ) {
		$option_type = is_array( $options ) ? ( $options['type'] ?? null ) : null;
		$type        = is_string( $option_type ) && '' !== $option_type ? strtolower( $option_type ) : null;
		if ( defender_is_wp_org_version() && in_array(
			$type,
			array(
				Scan_Item::TYPE_VULNERABILITY, // TYPE_SUSPICIOUS const is not suitable for use.
				'suspicious_code',

			),
			true
		) ) {
			WP_CLI::warning( 'A WPMU DEV subscription is required to use this command.' );
			return;
		}

		switch ( $type ) {
			case null:
				// All items.
				$type = null;
				break;
			case 'core_integrity':
				$type = Scan_Item::TYPE_INTEGRITY;
				break;
			case 'plugin_integrity':
				$type = Scan_Item::TYPE_PLUGIN_CHECK;
				break;
			case 'vulnerability':
				$type = Scan_Item::TYPE_VULNERABILITY;
				break;
			case 'suspicious_code':
				$type = Scan_Item::TYPE_SUSPICIOUS;
				break;
			case 'plugin_outdated':
				$type = Scan_Item::TYPE_PLUGIN_OUTDATED;
				break;
			case 'plugin_closed':
				$type = Scan_Item::TYPE_PLUGIN_CLOSED;
				break;
			default:
				WP_CLI::error( sprintf( 'Unknown scan type %s', $type ) );
				break;
		}
		$active = Model_Scan::get_active();
		if ( is_object( $active ) ) {
			WP_CLI::error( 'A scan is running, you need to wait till it complete to continue' );
		}
		$model = Model_Scan::get_last();
		if ( ! is_object( $model ) ) {
			return;
		}
		switch ( $command ) {
			case 'ignore':
				$issues = $model->get_issues( $type, Scan_Item::STATUS_ACTIVE );
				foreach ( $issues as $issue ) {
					$issue_data = $this->split_scan_issue_into_file_and_dir( $type, $issue->raw_data );
					if ( $model->ignore_issue( $issue->id ) ) {
						WP_CLI::log( sprintf( 'Ignoring %s: %s', $issue_data['type'], $issue_data['path'] ) );
					}
				}
				WP_CLI::log( sprintf( 'Ignored %s items', count( $issues ) ) );
				break;
			case 'unignore':
				$issues = $model->get_issues( $type, Scan_Item::STATUS_IGNORE );
				foreach ( $issues as $issue ) {
					$issue_data = $this->split_scan_issue_into_file_and_dir( $type, $issue->raw_data );
					if ( $model->unignore_issue( $issue->id ) ) {
						WP_CLI::log( sprintf( 'Unignoring %s: %s', $issue_data['type'], $issue_data['path'] ) );
					}
				}
				WP_CLI::log( sprintf( 'Unignored %s items', count( $issues ) ) );
				break;
			case 'resolve':
				$items    = $model->get_issues( $type, Scan_Item::STATUS_ACTIVE );
				$resolved = array();
				foreach ( $items as $item ) {
					if ( in_array( $item->type, array( Scan_Item::TYPE_INTEGRITY, Scan_Item::TYPE_PLUGIN_CHECK ), true ) ) {
						WP_CLI::log( sprintf( 'Reverting %s to original', $item->raw_data['file'] ) );
						$ret = $item->resolve();
						if ( ! is_wp_error( $ret ) ) {
							$resolved[] = $item;
						} else {
							WP_CLI::error( $ret->get_error_message() );
						}
					} elseif ( Scan_Item::TYPE_SUSPICIOUS === $item->type ) {
						// If this is content, we will try to delete them.
						$whitelist  = array(// wordfence waf.
							ABSPATH . '/wordfence-waf.php', // Any files inside plugins, if removed, can cause fatal error.
							WP_CONTENT_DIR . '/plugins/', // Any files inside themes.
							$this->get_path_of_themes_dir(),
						);
						$path       = $item->raw_data['file'];
						$can_delete = true;
						foreach ( $whitelist as $value ) {
							$current = $value;
							if ( str_contains( $path, $value ) ) {
								// Ignore this.
								$can_delete = false;
								break;
							}
						}
						if ( false === $can_delete ) {
							WP_CLI::log( sprintf( 'Ignore file %s as it is in %s', $path, $current ) );
						} elseif ( ! is_dir( $path ) && wp_delete_file( $path ) ) {
							WP_CLI::log( sprintf( 'Delete file %s', $path ) );
							$model->remove_issue( $item->id );
							$resolved[] = $item;
						} else {
							WP_CLI::error( sprintf( "Can't delete file %s", $path ) );
						}
					} elseif ( Scan_Item::TYPE_VULNERABILITY === $item->type ) {
						$ret = $item->resolve();
						if ( is_wp_error( $ret ) ) {
							WP_CLI::error( $ret->get_error_message() );
						} elseif ( is_array( $ret ) && isset( $ret['type_notice'] ) && 'error' === $ret['type_notice'] ) {
							WP_CLI::error( $ret['message'] ?? esc_html__( 'Unable to resolve vulnerability.', 'defender-security' ) );
						} else {
							$model->remove_issue( $item->id );
							$resolved[] = $item;
						}
					}
				}
				WP_CLI::log( sprintf( 'Resolved %s items', count( $resolved ) ) );
				break;
			case 'delete':
				$items   = $model->get_issues( $type, Scan_Item::STATUS_ACTIVE );
				$deleted = array();
				foreach ( $items as $item ) {
					$issue_data = $this->split_scan_issue_into_file_and_dir( $type, $item->raw_data );
					$path       = $issue_data['path'];
					$issue_type = $issue_data['type'];
					if ( ! file_exists( $path ) ) {
						continue;
					}
					// Work with plugin dir or single file, e.g. for Vulnerability, Outdated or Closed plugin types.
					if ( 'folder' === $issue_type ) {
						if ( $this->is_active_plugin( $path ) ) {
							WP_CLI::warning( sprintf( 'This plugin %s cannot be removed because it is active.', $path ) );
							continue;
						}

						if ( is_dir( $path ) ) {
							if ( $this->delete_dir( $path ) ) {
								WP_CLI::log( sprintf( 'Delete %s: %s', $issue_type, $path ) );
								$model->remove_issue( $item->id );
								$deleted[] = $item;
							}
						} elseif ( wp_delete_file( $path ) ) {
							WP_CLI::log( sprintf( 'Delete %s: %s', $issue_type, $path ) );
							$model->remove_issue( $item->id );
							$deleted[] = $item;
						} else {

							WP_CLI::error( sprintf( "Can't delete %s: %s", $issue_type, $path ) );
						}
					} elseif ( 'file' === $issue_type ) {
						// Work with core_integrity, plugin_integrity or suspicious_code types.
						if ( wp_delete_file( $path ) ) {
							WP_CLI::log( sprintf( 'Delete %s: %s', $issue_type, $path ) );
							$model->remove_issue( $item->id );
							$deleted[] = $item;
						} else {
							WP_CLI::warning( sprintf( "Can't delete %s: %s", $issue_type, $path ) );
						}
					}
				}
				WP_CLI::log( sprintf( 'Deleted %s items', count( $deleted ) ) );
				break;
			default:
				break;
		}
	}

	/**
	 * Split scan issue into file and dir.
	 *
	 * @param string|null $type Scan type.
	 * @param array       $raw_data Array of raw scan data.
	 *
	 * @return array
	 */
	private function split_scan_issue_into_file_and_dir( $type, $raw_data ): array {
		// General case without type-param.
		if ( null === $type ) {
			if ( isset( $raw_data['file'] ) ) {
				return array(
					'type' => 'file',
					'path' => $raw_data['file'],
				);
			} elseif ( isset( $raw_data['base_slug'] ) ) {
				return array(
					'type' => 'folder',
					'path' => $this->get_abs_plugin_path_by_slug( $raw_data['base_slug'] ),
				);
			} elseif ( isset( $raw_data['slug'] ) ) {
				return array(
					'type' => 'folder',
					'path' => $this->get_abs_plugin_path_by_slug( $raw_data['slug'] ),
				);
			}
		}

		if ( in_array( $type, array( Scan_Item::TYPE_PLUGIN_OUTDATED, Scan_Item::TYPE_PLUGIN_CLOSED ), true ) ) {
			return array(
				'type' => 'folder',
				'path' => $this->get_abs_plugin_path_by_slug( $raw_data['slug'] ),
			);
		} elseif ( Scan_Item::TYPE_VULNERABILITY === $type ) {
			return array(
				'type' => 'folder',
				'path' => $this->get_abs_plugin_path_by_slug( $raw_data['base_slug'] ),
			);
		} else {
			return array(
				'type' => 'file',
				'path' => $raw_data['file'],
			);
		}
	}

	/**
	 * Generate dummy data, use in unit tests.
	 * DO NOT USE IN PRODUCTION.
	 *
	 * @param mixed $args Command arguments.
	 */
	public function seed( $args ) {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}
		if ( ! is_array( $args ) || array() === $args ) {
			WP_CLI::error( 'Invalid command' );

			return;
		}
		[$command] = $args;
		switch ( $command ) {
			case 'scan:core':
				$file_path = ABSPATH . 'wp-load.php';
				$content   = '//this make different';
				if ( $wp_filesystem->exists( $file_path ) ) {
					$content = $wp_filesystem->get_contents( $file_path ) . $content;
				}
				$wp_filesystem->put_contents( $file_path, $content );
				break;
			case 'ip:logs':
				// We will generate randomly 10k logs in 3 months.
				$types   = array( Lockout_Log::AUTH_FAIL, Lockout_Log::AUTH_LOCK, Lockout_Log::ERROR_404, Lockout_Log::LOCKOUT_404, Lockout_Log::LOCKOUT_UA );
				$is_lock = array( Lockout_Log::AUTH_LOCK, Lockout_Log::LOCKOUT_404, Lockout_Log::LOCKOUT_UA );
				$faker   = Factory::create();
				WP_CLI::log( $faker->ipv4 );
				$range        = array(
					'today midnight' => array( 'now', 100 ),
					'-6 days'        => array( 'yesterday', 50 ),
					'-30 days'       => array( '-7 days', 70 ),
				);
				$counter      = array(
					'last_24_hours' => 0,
					'last_30_days'  => 0,
					'login_lockout' => 0,
					'404_lockout'   => 0,
					'ua_lockout'    => 0,
				);
				$last_lockout = 0;
				foreach ( $range as $date => $to ) {
					[$to, $count] = $to;
					for ( $i = 0; $i < $count; $i++ ) {
						$model                   = new Lockout_Log();
						$model->ip               = $faker->ipv4;
						$model->type             = $types[ array_rand( $types ) ];
						$model->log              = $faker->sentence( 20 );
						$model->date             = $faker->dateTimeBetween( $date, $to )->getTimestamp();
						$model->blog_id          = 1;
						$model->tried            = $faker->userName; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
						$model->country_iso_code = $faker->countryCode; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
						$model->save();
						if ( ( $model->date > $last_lockout ) ) {
							$last_lockout = $model->date;
						}
						if ( in_array( $model->type, $is_lock, true ) ) {
							$counter['last_30_days'] += 1;
							if ( $model->date > strtotime( 'yesterday midnight' ) ) {
								$counter['last_24_hours'] += 1;
							}
							if ( $model->date > strtotime( '-6 days', strtotime( 'today midnight' ) ) ) {
								if ( Lockout_Log::AUTH_LOCK === $model->type ) {
									$counter['login_lockout'] += 1;
								} elseif ( Lockout_Log::LOCKOUT_404 === $model->type ) {
									$counter['404_lockout'] += 1;
								} else {
									$counter['ua_lockout'] += 1;
								}
							}
						}
					}
				}
				$counter['last_lockout'] = $this->format_date_time( $last_lockout );
				echo wp_json_encode( $counter );
				break;
			default:
				WP_CLI::error( 'Invalid command' );
				break;
		}
	}

	/**
	 * Clean up dummy data.
	 * DO NOT USE IN PRODUCTION.
	 *
	 * @param mixed $args Command arguments.
	 */
	public function unseed( $args ) {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}
		if ( ! is_array( $args ) || array() === $args ) {
			WP_CLI::error( 'Invalid command' );

			return;
		}
		[$command] = $args;
		switch ( $command ) {
			case 'scan:core':
				$content = file_get_contents( ABSPATH . 'wp-load.php' );
				$wp_filesystem->put_contents( ABSPATH . 'wp-load.php', str_replace( '//this make different', '', $content ) );
				break;
			case 'scan:suspicious':
				wp_delete_file( WP_CONTENT_DIR . '/false-positive.php' );
				break;
			default:
				break;
		}
	}

	/**
	 * Manage audit logs via WP-CLI. Requires a WPMU DEV subscription.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : Action to perform.
	 * ---
	 * options:
	 *   - reset
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Delete all audit log entries from the database.
	 *     $ wp defender audit reset
	 *     All clear
	 *
	 * @param mixed $args Command arguments.
	 */
	public function audit( $args ) {
		if ( defender_is_wp_org_version() ) {
			WP_CLI::warning( 'A WPMU DEV subscription is required to use this command.' );
			return;
		}
	}

	/**
	 * Manage security headers via WP-CLI.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : Action to perform.
	 * ---
	 * options:
	 *   - check
	 *   - activate
	 *   - deactivate
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Check the current status of all security headers.
	 *     $ wp defender security_headers check
	 *     Success: Checking is ready.
	 *
	 *     # Activate all security headers.
	 *     $ wp defender security_headers activate
	 *     Activating is ready.
	 *
	 *     # Deactivate all security headers.
	 *     $ wp defender security_headers deactivate
	 *     Deactivating is ready.
	 *
	 * @param mixed $args Command arguments.
	 *
	 * @throws ExitException|Exception If an invalid command is provided.
	 */
	public function security_headers( $args ) {
		if ( ! is_array( $args ) || array() === $args ) {
			WP_CLI::error( 'Invalid command.' );

			return;
		}
		$model = new Security_Headers();
		[$command] = $args;
		switch ( $command ) {
			case 'check':
				$i = 1;
				foreach ( $model->get_headers() as $header ) {
					$state = true === $header->check() ? 'enabled' : 'disabled';
					WP_CLI::log( sprintf( '#%s - %s is %s', $i, $header->get_title(), $state ) );
					++$i;
				}
				WP_CLI::success( 'Checking is ready.' );
				break;
			case 'activate':
				foreach ( $model->get_headers() as $rule_slug => $header ) {
					$this->set_security_header_state( $model, $rule_slug, true );
				}
				$model->save();
				WP_CLI::log( 'Activating is ready.' );
				break;
			case 'deactivate':
				foreach ( $model->get_headers() as $rule_slug => $header ) {
					$this->set_security_header_state( $model, $rule_slug, false );
				}
				$model->save();
				WP_CLI::log( 'Deactivating is ready.' );
				break;
			default:
				WP_CLI::error( sprintf( 'Unknown command %s', $command ) );
				break;
		}
	}

	/**
	 * Set a security header setting without using dynamic model properties.
	 *
	 * @param Security_Headers $model The security headers settings model.
	 * @param string           $rule_slug The header rule slug.
	 * @param bool             $enabled Whether the rule is enabled.
	 */
	private function set_security_header_state( Security_Headers $model, string $rule_slug, bool $enabled ): void {
		switch ( $rule_slug ) {
			case 'sh_xframe':
				$model->sh_xframe = $enabled;
				break;
			case 'sh_xss_protection':
				$model->sh_xss_protection = $enabled;
				break;
			case 'sh_content_type_options':
				$model->sh_content_type_options = $enabled;
				break;
			case 'sh_strict_transport':
				$model->sh_strict_transport = $enabled;
				break;
			case 'sh_referrer_policy':
				$model->sh_referrer_policy = $enabled;
				break;
			case 'sh_feature_policy':
				$model->sh_feature_policy = $enabled;
				break;
		}
	}

	/**
	 * Manage plugin settings via WP-CLI.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : Action to perform.
	 * ---
	 * options:
	 *   - reset
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Reset all plugin settings to defaults.
	 *     $ wp defender settings reset
	 *     All cleared!
	 *
	 * @param mixed $args    Command arguments.
	 * @param mixed $options Command options.
	 */
	public function settings( $args, $options ) {
		if ( ! is_array( $args ) || array() === $args ) {
			WP_CLI::error( 'Invalid command, add necessary arguments. See below...', false );
			WP_CLI::runcommand( 'defender settings --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}

		[$command] = $args;
		switch ( $command ) {
			case 'reset':
				WP_CLI::confirm( 'This will completely reset the plugin settings, are you sure to continue?', $options );
				// Analog Settings > Reset Settings.
				wd_di()->get( Login_Access::class )->remove_settings();
				wd_di()->get( Dashboard::class )->remove_settings();
				wd_di()->get( Security_Tweaks::class )->remove_settings();
				wd_di()->get( \WP_Defender\Controller\Scan::class )->remove_settings();
				// Parent and submodules.
				wd_di()->get( \WP_Defender\Controller\Firewall::class )->remove_settings();

				wd_di()->get( \WP_Defender\Controller\Mask_Login::class )->remove_settings();
				wd_di()->get( \WP_Defender\Controller\Notification::class )->remove_settings();
				wd_di()->get( Two_Factor::class )->remove_settings();
				wd_di()->get( Main_Setting::class )->remove_settings();
				WP_CLI::log( 'All cleared!' );
				break;
			default:
				WP_CLI::error( sprintf( 'Unknown command %s, use correct arguments. See below...', $command ), false );
				WP_CLI::runcommand( 'defender settings --help', [ 'launch' => false, 'exit_error' => false ] );
				break;
		}
	}

	/**
	 * Manage firewall submodules, data, and lockouts via WP-CLI.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : Action to perform.
	 * ---
	 * options:
	 *   - clear
	 *   - unblock
	 *   - list
	 *   - activate
	 *   - deactivate
	 * ---
	 *
	 * <type>
	 * : The firewall data type to target (e.g. ip, user_agent, files, maxmind, submodule).
	 *
	 * [<field>]
	 * : The specific field or submodule to target. Defaults to 'all' for the list command.
	 *
	 * [--ips=<ips>]
	 * : Comma-separated list of IP addresses to unblock. Required for the unblock command.
	 *
	 * ## EXAMPLES
	 *
	 *     # Clear the IP allowlist.
	 *     $ wp defender firewall clear ip allowlist
	 *     Firewall allowlist ip is cleared.
	 *
	 *     # Unblock specific IPs from lockout.
	 *     $ wp defender firewall unblock ip lockout --ips=127.0.0.1,236.211.38.221
	 *     Firewall lockout ip unblocked
	 *
	 *     # List all user agent entries.
	 *     $ wp defender firewall list user_agent all
	 *
	 *     # Activate login protection submodule.
	 *     $ wp defender firewall activate submodule login_protection
	 *     Success: Firewall "Login Protection" has been activated.
	 *
	 *     # Deactivate 404 detection submodule.
	 *     $ wp defender firewall deactivate submodule 404_detection
	 *     Success: Firewall "404 Detection" has been deactivated.
	 *
	 * @param mixed $args    Command arguments.
	 * @param mixed $options Command options.
	 */
	public function firewall( $args, $options ) {
		$arg_count = is_array( $args ) || $args instanceof Countable ? count( $args ) : 0;
		if ( $arg_count < 2 ) {
			WP_CLI::error( 'Invalid command, add necessary arguments. See below...', false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}

		$command = $args[0];
		$type    = $args[1];
		// Field is optional for the 'list' command — defaults to 'all'.
		$field = $args[2] ?? ( 'list' === $command ? 'all' : '' );

		if ( ! is_string( $type ) || '' === $type ) {
			WP_CLI::error( 'Invalid option.', false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}
		switch ( $command ) {
			case 'clear':
				$this->clear_firewall( $type, $field );
				break;
			case 'unblock':
				$this->unblock_firewall( $type, $field, $options );
				break;
			case 'list':
				$this->list_firewall( $type, $field );
				break;
			case 'activate':
				$this->toggle_firewall_submodule( $type, $field, 'activate' );
				break;
			case 'deactivate':
				$this->toggle_firewall_submodule( $type, $field, 'deactivate' );
				break;
			default:
				WP_CLI::error( sprintf( 'Unknown command %s', $command ) );
				break;
		}
	}

	/**
	 * Clears the firewall data based on the specified type and field.
	 *
	 * @param string $type The type of data to clear.
	 * @param string $field The specific field to clear.
	 */
	private function clear_firewall( $type, $field ) {
		$type_default  = array( 'ip', 'files', 'user_agent', 'maxmind' );
		$field_default = array( 'blocklist', 'allowlist', 'country_allowlist', 'country_blocklist', 'license_key' );

		if ( ! in_array( $type, $type_default, true ) ) {
			WP_CLI::error( sprintf( 'Invalid option %s. See below...', $type ), false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}

		if ( ! in_array( $field, $field_default, true ) ) {
			WP_CLI::error( sprintf( 'Invalid option %s. See below...', $field ), false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}

		// Rename the field's name to original model field name.
		$original_field = $this->rename_field( $field );
		if ( 'ip' === $type ) {
			// Get the model instance.
			$model = wd_di()->get( \WP_Defender\Model\Setting\Blacklist_Lockout::class );
			$data  = $model->export();
			// Rename the field to match with the appropriate model field name.
			$mod_field = $this->is_country( $original_field ) ? $original_field : 'ip_' . $original_field;
			// Reset to default data with correct data type.
			$default_data = $this->is_country( $original_field ) ? array() : '';
			// Empty the $field option of field data.
			$data[ $mod_field ] = $default_data;
			$model->import( $data );
			$model->save();
		} elseif ( 'files' === $type ) {
			// Get the model instance.
			$model = wd_di()->get( Notfound_Lockout::class );
			$data  = $model->export();
			// Empty the $field option of field data.
			$data[ $original_field ] = '';
			$model->import( $data );
			$model->save();
		} elseif ( 'user_agent' === $type ) {
			$model                   = wd_di()->get( User_Agent_Lockout::class );
			$data                    = $model->export();
			$data[ $original_field ] = '';
			$model->import( $data );
			$model->save();
		} elseif ( 'maxmind' === $type ) {
			try {
				$model = wd_di()->get( \WP_Defender\Model\Setting\Blacklist_Lockout::class );
				if ( ! is_null( $model->geodb_path ) && is_file( $model->geodb_path ) ) {
					wp_delete_file( $model->geodb_path );
				}
				$model->maxmind_license_key = '';
				$model->geodb_path          = '';
				$model->save();
			} catch ( Throwable $th ) {
				WP_CLI::log( $th->getMessage() );
			}
		}

		WP_CLI::log( sprintf( 'Firewall %s %s is cleared.', str_replace( '_', ' ', $field ), $type ) );
	}

	/**
	 * Rename a field to its original model field name.
	 *
	 * @param string $field The field name to rename.
	 *
	 * @return string The renamed field name.
	 */
	private function rename_field( $field ) {
		if ( '' !== $field ) {
			return str_replace( array( 'allow', 'block' ), array( 'white', 'black' ), $field );
		}

		return '';
	}

	/**
	 * Check if the specified field is related to country settings.
	 *
	 * @param string $field The field to check.
	 *
	 * @return bool True if the field is related to country settings, false otherwise.
	 */
	private function is_country( $field ) {
		return ( 'country_whitelist' === $field || 'country_blacklist' === $field );
	}

	/**
	 * Unblocks the specified IPs from the firewall.
	 *
	 * @param string $type The type of data to unblock.
	 * @param string $field The specific field to unblock.
	 * @param array  $options Command options including IPs to unblock.
	 */
	private function unblock_firewall( $type, $field, $options ) {
		$type_default  = array( 'ip' );
		$field_default = array( 'lockout' );

		if ( ! in_array( $type, $type_default, true ) ) {
			WP_CLI::error( sprintf( 'Invalid option %s. See below...', $type ), false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}

		if ( ! in_array( $field, $field_default, true ) ) {
			WP_CLI::error( sprintf( 'Invalid option %s. See below...', $field ), false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}

		if ( array_key_exists( 'ips', $options ) ) {
			$ips    = array_map( 'trim', explode( ',', $options['ips'] ) );
			$models = Lockout_Ip::get_bulk( Lockout_Ip::STATUS_BLOCKED, $ips );

			foreach ( $models as $model ) {
				$model->status = Lockout_Ip::STATUS_NORMAL;
				$model->save();
			}
		} else {
			WP_CLI::error( 'Option \'ips\' is not provided. See below...', false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}

		WP_CLI::log( sprintf( 'Firewall %s %s unblocked', str_replace( '_', ' ', $field ), $type ) );
	}

	/**
	 * Lists details for the firewall based on the specified type and field.
	 * Example: wp defender firewall list user_agent all
	 *
	 * @param string $type The type of data to list.
	 * @param string $field The specific field to list.
	 *
	 * @since v2.6.4. Add the details for User Agent Banning.
	 */
	private function list_firewall( $type, $field ) {
		$type_default  = array( 'user_agent' );
		$field_default = array( 'all', 'allowlist', 'blocklist' );
		if ( ! in_array( $type, $type_default, true ) ) {
			WP_CLI::error( sprintf( 'Invalid option %s. See below...', $type ), false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}
		if ( ! in_array( $field, $field_default, true ) ) {
			WP_CLI::error( sprintf( 'Invalid option %s. See below...', $field ), false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}
		$model = wd_di()->get( User_Agent_Lockout::class );
		$data  = $model->export();
		if ( 'all' === $field && isset( $data['whitelist'] ) && '' !== $data['whitelist'] && isset( $data['blacklist'] ) && '' !== $data['blacklist'] ) {
			WP_CLI::log( 'ALLOWLIST:' );
			WP_CLI::log( $data['whitelist'] );
			WP_CLI::log( 'BLOCKLIST:' );
			WP_CLI::log( $data['blacklist'] );
		} elseif ( 'allowlist' === $field && isset( $data['whitelist'] ) && '' !== $data['whitelist'] ) {
			WP_CLI::log( $data['whitelist'] );
		} elseif ( 'blocklist' === $field && isset( $data['blacklist'] ) && '' !== $data['blacklist'] ) {
			WP_CLI::log( $data['blacklist'] );
		} else {
			WP_CLI::log( 'No data.' );
		}
	}

	/**
	 * Change status of Firewall submodules: login_protection, 404_detection or user_agent.
	 * Example: wp defender firewall activate submodule user_agent
	 * Example: wp defender firewall deactivate submodule login_protection
	 *
	 * @param string $key_word The keyword to identify the action.
	 * @param string $submodule The submodule to toggle.
	 * @param string $action The action to perform (activate or deactivate).
	 */
	private function toggle_firewall_submodule( $key_word, $submodule, $action ) {
		if ( 'submodule' !== $key_word ) {
			WP_CLI::error( sprintf( 'Invalid option %s. See below...', $key_word ), false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}
		if ( ! in_array( $submodule, array( 'login_protection', '404_detection', 'user_agent' ), true ) ) {
			WP_CLI::error( sprintf( 'Invalid option %s. See below...', $submodule ), false );
			WP_CLI::runcommand( 'defender firewall --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}
		// Get submodule slug.
		if ( 'login_protection' === $submodule ) {
			$model     = wd_di()->get( Login_Lockout::class );
			$submodule = Login_Lockout::get_module_name();
		} elseif ( '404_detection' === $submodule ) {
			$model     = wd_di()->get( Notfound_Lockout::class );
			$submodule = Notfound_Lockout::get_module_name();
		} else {
			$model     = wd_di()->get( User_Agent_Lockout::class );
			$submodule = User_Agent_Lockout::get_module_name();
		}
		// Activate/deactivate submodule.
		if ( 'activate' === $action ) {
			$text = 'activated';
			// Check if the submodule is not yet activated.
			if ( true !== $model->enabled ) {
				$model->enabled = true;
				$model->save();
			}
		} else {
			$text = 'deactivated';
			// Check if the submodule is not yet deactivated.
			if ( false !== $model->enabled ) {
				$model->enabled = false;
				$model->save();
			}
		}

		WP_CLI::success( sprintf( 'Firewall "%s" has been %s.', $submodule, $text ) );
	}

	/**
	 * Manage mask login settings via WP-CLI.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : Action to perform.
	 * ---
	 * options:
	 *   - clear
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Reset all mask login settings to defaults.
	 *     $ wp defender mask_login clear
	 *     Mask login settings cleared!
	 *
	 * @param mixed $args Command arguments.
	 */
	public function mask_login( $args ) {
		if ( ( is_array( $args ) || $args instanceof Countable ? count( $args ) : 0 ) < 1 ) {
			WP_CLI::error( 'Invalid command, add necessary arguments. See below...', false );
			WP_CLI::runcommand( 'defender mask_login --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}

		[$command] = $args;
		switch ( $command ) {
			case 'clear':
				wd_di()->get( \WP_Defender\Model\Setting\Mask_Login::class )->delete();
				WP_CLI::log( 'Mask login settings cleared!' );
				break;
			default:
				WP_CLI::error( sprintf( 'Unknown command %s', $command ) );
				break;
		}
	}

	/**
	 * Manage bulk password reset via WP-CLI.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : Action to perform.
	 * ---
	 * options:
	 *   - force
	 *   - undo
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Force all users to reset their password on next login.
	 *     $ wp defender password_reset force
	 *
	 *     # Cancel a previously forced password reset.
	 *     $ wp defender password_reset undo
	 *     Passwords reset is no longer required.
	 *
	 * @param mixed $args Command arguments.
	 */
	public function password_reset( $args ) {
		if ( ( is_array( $args ) || $args instanceof Countable ? count( $args ) : 0 ) < 1 ) {
			WP_CLI::error( 'Invalid command.' );

			return;
		}

		[$command] = $args;
		switch ( $command ) {
			case 'force':
				// Get the model instance.
				$model               = wd_di()->get( Password_Reset::class );
				$model->expire_force = true;
				$model->force_time   = time();
				$model->save();
				$message = sprintf( 'Passwords created before %s are required to be reset upon next login.', $this->format_date_time( $model->force_time ) );
				WP_CLI::log( $message );
				break;
			case 'undo':
				$model               = wd_di()->get( Password_Reset::class );
				$model->expire_force = false;
				$model->save();
				WP_CLI::log( 'Passwords reset is no longer required.' );
				break;
			default:
				WP_CLI::error( sprintf( 'Unknown command %s', $command ) );
				break;
		}
	}

	/**
	 * Manage Defender's internal log files.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : Action to perform.
	 * ---
	 * options:
	 *   - delete
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Delete log files older than one week.
	 *     $ wp defender logs delete
	 *     Logs older than a week have been deleted.
	 *
	 * @param mixed $args Command arguments.
	 */
	public function logs( $args ) {
		if ( ( is_array( $args ) || $args instanceof Countable ? count( $args ) : 0 ) < 1 ) {
			WP_CLI::error( 'Invalid command, add necessary arguments. See below...', false );
			WP_CLI::runcommand( 'defender logs --help', [ 'launch' => false, 'exit_error' => false ] );

			return;
		}

		[$command] = $args;

		switch ( $command ) {
			case 'delete':
				$rotation_logger = wd_di()->get( Rotation_Logger::class );
				$rotation_logger->purge_old_log();
				WP_CLI::log( 'Logs older than a week have been deleted.' );
				break;
			default:
				WP_CLI::error( sprintf( 'Unknown command %s', $command ) );
				break;
		}
	}

	/**
	 * Manage CAPTCHA settings via WP-CLI.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : Action to perform.
	 * ---
	 * options:
	 *   - activate
	 *   - deactivate
	 *   - clear
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Enable CAPTCHA.
	 *     $ wp defender captcha activate
	 *     CAPTCHA is activated.
	 *
	 *     # Disable CAPTCHA.
	 *     $ wp defender captcha deactivate
	 *     CAPTCHA is deactivated.
	 *
	 *     # Reset all CAPTCHA settings to defaults.
	 *     $ wp defender captcha clear
	 *     CAPTCHA is cleared.
	 *
	 * @param mixed $args Command arguments.
	 */
	public function captcha( $args ) {
		if ( ! is_array( $args ) || array() === $args ) {
			WP_CLI::error( 'Invalid command.' );

			return;
		}
		$model     = wd_di()->get( \WP_Defender\Model\Setting\Captcha::class );
		[$command] = $args;
		switch ( $command ) {
			case 'activate':
				if ( true !== $model->enabled ) {
					$model->enabled = true;
					$model->save();
				}
				WP_CLI::log( 'CAPTCHA is activated.' );
				break;
			case 'deactivate':
				if ( false !== $model->enabled ) {
					$model->enabled = false;
					$model->save();
				}
				WP_CLI::log( 'CAPTCHA is deactivated.' );
				break;
			case 'clear':
				$default_values                      = $model->get_default_values();
				$model->message                      = $default_values['message'];
				$model->language                     = 'automatic';
				$model->provider                     = 'recaptcha';
				$model->data_v2_checkbox             = array(
					'key'    => '',
					'secret' => '',
					'size'   => 'normal',
					'style'  => 'light',
				);
				$model->data_v2_invisible            = array(
					'key'    => '',
					'secret' => '',
				);
				$model->data_v3_recaptcha            = array(
					'key'       => '',
					'secret'    => '',
					'threshold' => '0.5',
				);
				$model->data_turnstile               = array(
					'key'      => '',
					'secret'   => '',
					'size'     => 'normal',
					'style'    => 'auto',
					'message'  => $default_values['turnstile_message'],
					'language' => 'auto',
				);
				$model->locations                    = array();
				$model->detect_woo                   = false;
				$model->woo_checked_locations        = array();
				$model->detect_buddypress            = false;
				$model->buddypress_checked_locations = array();
				$model->disable_for_known_users      = true;
				$model->save();

				WP_CLI::log( 'CAPTCHA is cleared.' );
				break;
			default:
				WP_CLI::error( sprintf( 'Unknown command %s.', $command ) );
				break;
		}
	}
}
