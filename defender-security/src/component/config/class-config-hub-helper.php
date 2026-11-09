<?php
/**
 * Handles interactions with the WPMU DEV Hub for configurations storage and retrieval.
 *
 * @package    WP_Defender\Component\Config
 */

namespace WP_Defender\Component\Config;

use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component\Backup_Settings;

/**
 * Handles configuration settings related to the WPMU DEV Hub.
 */
class Config_Hub_Helper {

	public const CONFIGS_TRANSIENT_KEY      = 'wpdefender_preset_configs';
	public const CONFIGS_TRANSIENT_TIME_KEY = 'wpdefender_preset_configs_transient_time';
	public const ACTIVE_FLAG_CLEAR_KEY      = 'wpdefender_config_clear_active_tag';
	public const CONFIGS_TRANSIENT_TIME     = 600; // 600 = 10 minutes.
	public const DELETED_HUB_IDS_OPTION     = 'wpdefender_deleted_hub_config_ids';

	/**
	 * WPMU DEV Plugin ID.
	 */
	public const WDP_ID = 1081723;

	/**
	 * Service class.
	 *
	 * @var Backup_Settings
	 */
	private $service;

	/**
	 * Get configs from transient.
	 *
	 * @param  Backup_Settings $service  Config service.
	 *
	 * @return mixed|array
	 */
	public static function get_configs( Backup_Settings $service ) {
		$configs = get_site_transient( self::CONFIGS_TRANSIENT_KEY );

		if ( false === $configs ) {
			$_this          = new self();
			$_this->service = $service;
			$configs        = $_this->fetch_current_configs();

			set_site_transient( self::CONFIGS_TRANSIENT_KEY, $configs, self::CONFIGS_TRANSIENT_TIME );
			update_site_option( self::CONFIGS_TRANSIENT_TIME_KEY, time() );
		}

		return $configs;
	}

	/**
	 * Push unsynced local configs to the Hub and merge Hub configs into local storage.
	 *
	 * Replaces the legacy per-option sync path: Hub IDs and Hub-originated configs are
	 * persisted in Local_Config_Store instead of individual site options.
	 *
	 * @param  Local_Config_Store $local_store  Local config store.
	 * @param  Backup_Settings    $service  Config service.
	 *
	 * @return array Synced configs, keyed by config key.
	 */
	public static function sync_with_hub( Local_Config_Store $local_store, Backup_Settings $service ): array {
		$_this          = new self();
		$_this->service = $service;
		$wpmudev        = new WPMUDEV();
		$def_details    = $_this->get_plugin_details();

		$configs = $local_store->get_all();

		// Push local configs that have no hub_id yet, and persist the IDs we get back.
		$pushed_hub_ids = array();
		foreach ( $configs as $key => &$config ) {
			if ( ! is_array( $config ) || isset( $config['hub_id'] ) ) {
				continue;
			}

			// Default/immortal configs are never pushed to the Hub.
			if ( str_starts_with( (string) $key, 'wp_defender_config_default' )
			     || ( isset( $config['immortal'] ) && true === (bool) $config['immortal'] )
			) {
				continue;
			}

			$hub_id = $_this->insert_to_hub( $config, $def_details, $wpmudev );
			if ( ! $hub_id ) {
				// Upload failed: keep the local config as-is, retry on the next sync.
				continue;
			}

			$hub_id           = (int) $hub_id;
			$config['hub_id'] = $hub_id;
			$pushed_hub_ids[] = $hub_id;
		}
		unset( $config );

		// Persist assigned Hub IDs now, so they survive a failing fetch below.
		if ( $pushed_hub_ids ) {
			$local_store->save_all( $configs );
		}

		if ( ! defined( WPMUDEV::class . '::API_PACKAGE_CONFIGS' ) ) {
			return $configs;
		}

		$response = $wpmudev->make_wpmu_request(
			WPMUDEV::API_PACKAGE_CONFIGS,
			array( 'package_id' => $def_details['id'] ),
			array( 'method' => 'GET' )
		);

		// Failed fetch or an error body instead of a config list: never drop local data.
		// An empty list is valid and must still prune; a malformed one must not.
		if ( ! self::is_hub_config_list( $response ) ) {
			return $configs;
		}

		$merged = $_this->merge_hub_configs( $response, $configs, $pushed_hub_ids );

		$local_store->save_all( $merged );
		self::clear_config_transient();

		return $merged;
	}

	/**
	 * Check a Hub response really is a config list and not an error body.
	 *
	 * The Hub returns a numerically-indexed list of config objects. An error body is an
	 * associative array, which would otherwise look like a list with no recognisable
	 * entries and prune every synced local config. An empty list is valid.
	 *
	 * @param  mixed $response  Response from the Hub.
	 *
	 * @return bool
	 */
	private static function is_hub_config_list( $response ): bool {
		if ( ! is_array( $response ) ) {
			return false;
		}

		if ( array() === $response ) {
			return true;
		}

		// Reject associative bodies, e.g. array( 'error' => '...' ).
		if ( array_keys( $response ) !== range( 0, count( $response ) - 1 ) ) {
			return false;
		}

		// Every entry must be a config object carrying an id.
		foreach ( $response as $api_config ) {
			if ( ! is_array( $api_config ) || ! isset( $api_config['id'] ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Merge a successful Hub config list into the local config set.
	 *
	 * @param  array $response  Hub config list.
	 * @param  array $configs  Local configs keyed by config key.
	 * @param  array $exclude_prune_hub_ids  Hub IDs protected from pruning (e.g. freshly pushed).
	 *
	 * @return array
	 */
	private function merge_hub_configs( array $response, array $configs, array $exclude_prune_hub_ids = array() ): array {
		$deleted_hub_ids = get_site_option( self::DELETED_HUB_IDS_OPTION, array() );
		$deleted_hub_ids = is_array( $deleted_hub_ids ) ? array_map( 'intval', $deleted_hub_ids ) : array();

		// Build hub_id (int) => local key map for O(1) matching and type normalization.
		$hub_id_to_key = array();
		foreach ( $configs as $key => $config ) {
			if ( ! is_array( $config ) || ! isset( $config['hub_id'] ) ) {
				continue;
			}

			$hub_id_to_key[ (int) $config['hub_id'] ] = $key;
		}

		// Hub IDs present in the response, so we can drop locals the Hub no longer has.
		$seen_hub_ids = array();

		foreach ( $response as $api_config ) {
			$api_id = (int) $api_config['id'];

			// Honour local deletions that are not yet reflected on the Hub.
			if ( in_array( $api_id, $deleted_hub_ids, true ) ) {
				continue;
			}

			$seen_hub_ids[] = $api_id;

			if ( isset( $hub_id_to_key[ $api_id ] ) ) {
				$matched_key                             = $hub_id_to_key[ $api_id ];
				$hub_config                              = $this->format_hub_config_to_save( $api_config );
				$configs[ $matched_key ]['name']         = $hub_config['name'];
				$configs[ $matched_key ]['description']  = $hub_config['description'];
				$configs[ $matched_key ]['immortal']     = $hub_config['immortal'];
				$configs[ $matched_key ]['is_removable'] = $hub_config['is_removable'];
				continue;
			}

			// New config coming from the Hub.
			$key               = 'wp_defender_config_hub_' . $api_id;
			$hub_config        = $this->format_hub_config_to_save( $api_config );
			$hub_config['key'] = $key;
			$configs[ $key ]   = array_merge(
				array(
					'note_added_time' => '',
					'is_active'       => false,
					'date'            => (string) time(),
				),
				$configs[ $key ] ?? array(),
				$hub_config
			);
			$hub_id_to_key[ $api_id ] = $key;
		}

		return $this->prune_unlisted_configs( $configs, $seen_hub_ids, $exclude_prune_hub_ids );
	}

	/**
	 * Drop synced locals the Hub no longer lists.
	 *
	 * Untracked locals (no hub_id), freshly pushed configs, default and immortal configs are always kept.
	 *
	 * @param  array $configs  Local configs keyed by config key.
	 * @param  array $seen_hub_ids  Hub IDs present in the response.
	 * @param  array $exclude_hub_ids  Hub IDs protected from pruning.
	 *
	 * @return array
	 */
	private function prune_unlisted_configs( array $configs, array $seen_hub_ids, array $exclude_hub_ids ): array {
		$exclude_hub_ids = array_map( 'intval', $exclude_hub_ids );
		foreach ( $configs as $key => $config ) {
			if ( ! is_array( $config ) || ! isset( $config['hub_id'] ) ) {
				continue;
			}

			$local_hub_id = (int) $config['hub_id'];

			if ( in_array( $local_hub_id, $seen_hub_ids, true )
				|| in_array( $local_hub_id, $exclude_hub_ids, true )
			) {
				continue;
			}

			$is_removable = ! isset( $config['is_removable'] ) || (bool) $config['is_removable'];
			$is_immortal  = isset( $config['immortal'] ) && (bool) $config['immortal'];
			if ( ! $is_removable || $is_immortal ) {
				continue;
			}

			unset( $configs[ $key ] );
		}

		return $configs;
	}

	/**
	 * Get our special WDP ID header line from the file.
	 *
	 * @return array Plugin details: name, id.
	 */
	private function get_plugin_details(): array {
		$wpmudev = new WPMUDEV();

		return array(
			'name' => 'Defender' . ( $wpmudev->is_pro() ? ' Pro' : '' ),
			'id'   => (string) self::WDP_ID,
		);
	}

	/**
	 * Fetch and prepare configs to store to transient.
	 *
	 * @return array
	 */
	private function fetch_current_configs(): array {
		$stored_configs = $this->service->get_configs();
		$wpmudev        = new WPMUDEV();
		$def_details    = $this->get_plugin_details();

		// Check config has `hub_id`. If not then send request to HUB and set it.
		$stored_configs = $this->check_and_save_configs_to_hub( $stored_configs, $def_details, $wpmudev );

		if ( defined( WPMUDEV::class . '::API_PACKAGE_CONFIGS' ) ) {
			// Fetch configs from API.
			$response = $wpmudev->make_wpmu_request(
				WPMUDEV::API_PACKAGE_CONFIGS,
				array( 'package_id' => $def_details['id'] ),
				array( 'method' => 'GET' )
			);
		} else {
			$response = false;
		}

		$final_configs = array();

		// Loop to set default config.
		// Exclude default config from match with HUB config.
		foreach ( $stored_configs as $sc_key => $sc_value ) {
			if ( str_starts_with( $sc_key, 'wp_defender_config_default' ) ) {
				$final_configs[ $sc_key ] = $sc_value;
				break;
			}

			// Sometimes key does not match for default config.
			if ( isset( $sc_value['immortal'] ) && $sc_value['immortal'] ) {
				$final_configs[ $sc_key ] = $sc_value;
				break;
			}
		}

		return $this->prepare_hub_configs_response( $response, $final_configs, $stored_configs );
	}

	/**
	 * Check configs are saved on hub. If not in hub then create it.
	 *
	 * @param  array   $stored_configs  All configs from DB.
	 * @param  array   $def_details  Defender plugin details.
	 * @param  WPMUDEV $wpmudev  Defender plugin details.
	 *
	 * @return array
	 */
	private function check_and_save_configs_to_hub( array $stored_configs, array $def_details, $wpmudev ): array {
		foreach ( $stored_configs as $sc_key => &$sc_value ) {
			// Check it is for default config.
			if ( str_starts_with( $sc_key, 'wp_defender_config_default' ) ) {
				continue;
			}

			// Sometimes key does not match for default config.
			if ( isset( $sc_value['immortal'] ) && $sc_value['immortal'] ) {
				continue;
			}

			if ( isset( $sc_value['hub_id'] ) ) {
				continue;
			}

			$hub_id = $this->insert_to_hub( $sc_value, $def_details, $wpmudev );

			// If data is not inserted to HUB.
			if ( ! $hub_id ) {
				continue;
			}

			$sc_value['hub_id'] = $hub_id;

			update_site_option( $sc_key, $sc_value );
		}

		return $stored_configs;
	}

	/**
	 * Insert new config to hub.
	 *
	 * @param  array   $sc_value  Single config from DB.
	 * @param  array   $def_details  Defender plugin details.
	 * @param  WPMUDEV $wpmudev  Defender plugin details.
	 *
	 * @return bool|int ID from hub.
	 */
	private function insert_to_hub( array $sc_value, array $def_details, $wpmudev ) {
		if ( ! defined( WPMUDEV::class . '::API_PACKAGE_CONFIGS' ) ) {
			return false;
		}

		if ( ! isset( $sc_value['configs'] ) || ! is_array( $sc_value['configs'] ) || array() === $sc_value['configs'] ) {
			return false;
		}

		if ( ! isset( $sc_value['labels'] ) || ! is_array( $sc_value['labels'] ) || array() === $sc_value['labels'] ) {
			$config_component   = wd_di()->get( Backup_Settings::class );
			$sc_value['labels'] = $config_component->prepare_config_labels( $sc_value['configs'] );
		}

		$data = array(
			'name'        => $sc_value['name'],
			'description' => $sc_value['description'],
			'package'     => $def_details,
			'config'      => wp_json_encode(
				array(
					'strings' => $sc_value['strings'],
					'configs' => $sc_value['configs'],
					'labels'  => $sc_value['labels'],
				)
			),
		);

		$response = $wpmudev->make_wpmu_request(
			WPMUDEV::API_PACKAGE_CONFIGS,
			$data,
			array( 'method' => 'POST' )
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		return $response['id'];
	}

	/**
	 * Add config to HUB.
	 *
	 * @param  array $data  Config data.
	 *
	 * @return bool|int
	 */
	public static function add_configs_to_hub( array $data ) {
		$_this       = new self();
		$wpmudev     = new WPMUDEV();
		$def_details = $_this->get_plugin_details();

		delete_site_transient( self::CONFIGS_TRANSIENT_KEY );

		return $_this->insert_to_hub( $data, $def_details, $wpmudev );
	}

	/**
	 * Delete config from HUB.
	 *
	 * @param  int $hub_id  ID of config from HUB.
	 *
	 * @return bool
	 */
	public static function delete_configs_from_hub( int $hub_id ): bool {
		// Always tombstone the hub_id locally, so Hub re-sync can't re-create it.
		self::add_deleted_hub_id( $hub_id );

		if ( ! defined( WPMUDEV::class . '::API_PACKAGE_CONFIGS' ) ) {
			return false;
		}

		$wpmudev  = new WPMUDEV();
		$url      = $wpmudev->get_endpoint( WPMUDEV::API_PACKAGE_CONFIGS );
		$response = self::send_request(
			$url . '/' . $hub_id,
			array(),
			$wpmudev->get_apikey(),
			'DELETE'
		);
		// Emergency exit, for example, if the API key is not valid.
		if ( ! is_array( $response ) ) {
			return false;
		}

		if ( isset( $response['deleted'] ) && $response['deleted'] ) {
			delete_site_transient( self::CONFIGS_TRANSIENT_KEY );
			self::remove_deleted_hub_id( $hub_id );

			return true;
		}

		return false;
	}

	/**
	 * Add a Hub config ID to the locally-deleted blocklist.
	 *
	 * @param  int $hub_id  The Hub config ID.
	 */
	public static function add_deleted_hub_id( int $hub_id ): void {
		$ids   = get_site_option( self::DELETED_HUB_IDS_OPTION, array() );
		$ids[] = $hub_id;
		update_site_option( self::DELETED_HUB_IDS_OPTION, array_unique( $ids ) );
	}

	/**
	 * Remove a Hub config ID from the locally-deleted blocklist.
	 *
	 * @param  int $hub_id  The Hub config ID.
	 */
	public static function remove_deleted_hub_id( int $hub_id ): void {
		$ids = get_site_option( self::DELETED_HUB_IDS_OPTION, array() );
		$ids = array_values( array_filter( $ids, fn( $id ) => $id !== $hub_id ) );
		update_site_option( self::DELETED_HUB_IDS_OPTION, $ids );
	}

	/**
	 * Update config on HUB.
	 *
	 * @param  array $config  Full config data.
	 *
	 * @return bool
	 */
	public static function update_on_hub( array $config ): bool {
		if ( ! isset( $config['hub_id'] ) ) {
			return false;
		}

		if ( ! defined( WPMUDEV::class . '::API_PACKAGE_CONFIGS' ) ) {
			return false;
		}

		$wpmudev = new WPMUDEV();
		$url     = $wpmudev->get_endpoint( WPMUDEV::API_PACKAGE_CONFIGS );

		$data = array(
			'name'        => $config['name'],
			'description' => $config['description'],
		);

		$response = self::send_request(
			$url . '/' . $config['hub_id'],
			$data,
			$wpmudev->get_apikey(),
			'PUT'
		);
		// Emergency exit, for example, if the API key is not valid.
		if ( ! is_array( $response ) ) {
			return false;
		}

		if ( isset( $response['id'] ) && $response['id'] ) {
			delete_site_transient( self::CONFIGS_TRANSIENT_KEY );

			return true;
		}

		return false;
	}

	/**
	 * Sends an API request to the specified URL.
	 *
	 * @param  string $url  URL to send the request to.
	 * @param  array  $body  Body of the request.
	 * @param  mixed  $api_key  API key for authorization.
	 * @param  string $method  HTTP method to be used (GET, POST, PUT, DELETE).
	 *
	 * @return bool|array
	 */
	private static function send_request( string $url, array $body, $api_key, string $method ) {
		if ( false === $api_key || '' === $api_key ) {
			return false;
		}

		$request = wp_remote_request(
			$url,
			array(
				'method'  => $method,
				'headers' => array(
					'Authorization' => $api_key,
				),
				'body'    => $body,
			)
		);

		if ( is_wp_error( $request ) ) {
			return false;
		}

		return json_decode( $request['body'], true );
	}

	/**
	 * Delete transient for matching condition.
	 *
	 * @return void
	 */
	public static function clear_config_transient(): void {
		delete_site_transient( self::CONFIGS_TRANSIENT_KEY );
	}

	/**
	 * Prepare configs getting from HUB.
	 *
	 * @param  mixed $response  Response from the HUB.
	 * @param  array $final_configs  Final configurations to be prepared.
	 * @param  array $stored_configs  Stored configurations for comparison.
	 *
	 * @return array
	 */
	private function prepare_hub_configs_response( $response, array $final_configs, array $stored_configs ): array {
		if ( ! is_array( $response ) || is_wp_error( $response ) ) {
			return $stored_configs;
		}

		$deleted_hub_ids = get_site_option( self::DELETED_HUB_IDS_OPTION, array() );

		// Store id of keys that need to delete. Because they are deleted on HUB.
		$delete_hub_ids    = array();
		$once_delete_unset = array();

		// Loop through all items found in the API.
		foreach ( $response as $api_config ) {
			// Skip configs that were explicitly deleted locally but not yet removed from Hub.
			if ( in_array( $api_config['id'], $deleted_hub_ids, true ) ) {
				continue;
			}

			$found            = false;
			$api_config_array = json_decode( $api_config['config'], true );

			// Find key and value from stored configs.
			foreach ( $stored_configs as $sc_key => $sc_value ) {
				if ( isset( $sc_value['hub_id'] ) ) {
					// Once it is unset from the deleted array don't re-add it.
					if ( ! isset( $once_delete_unset[ $sc_value['hub_id'] ] ) ) {
						$delete_hub_ids[ $sc_value['hub_id'] ] = $sc_key;
					}

					if ( $sc_value['hub_id'] === $api_config['id'] ) {
						// Sanitize data.
						$sc_value['name']         = sanitize_text_field( $api_config['name'] );
						$sc_value['description']  = ! isset( $api_config['description'] ) || ! is_string( $api_config['description'] )
							? ''
							: sanitize_textarea_field( $api_config['description'] );
						$sc_value['immortal']     = $api_config_array['immortal'] ?? $sc_value['immortal'];
						$sc_value['is_removable'] = $api_config['is_removable'] ?? true;
						$final_configs[ $sc_key ] = $sc_value;
						$found                    = true;

						unset( $delete_hub_ids[ $sc_value['hub_id'] ] );
						$once_delete_unset[ $sc_value['hub_id'] ] = $sc_key;
						break;
					}
				}
			}

			if ( $found ) {
				continue;
			}

			// Need to prepare this data because these are coming from HUB.
			$key                   = 'wp_defender_config_hub_' . $api_config['id'];
			$final_configs[ $key ] = $this->format_hub_config_to_save( $api_config );
			$this->service->index_key( $key );
		}

		$this->delete_hub_removed_configs( $delete_hub_ids );

		return $final_configs;
	}

	/**
	 * Delete configs that are delete from HUB.
	 *
	 * @param  array $delete_hub_ids  Array of configuration IDs to be deleted.
	 *
	 * @return void
	 */
	private function delete_hub_removed_configs( array $delete_hub_ids ): void {
		foreach ( $delete_hub_ids as $key ) {
			delete_site_option( $key );
			$this->service->remove_index( $key );
		}
	}

	/**
	 * Need to prepare this data because these are coming from HUB.
	 *
	 * @param  array $api_config  The hub config data.
	 *
	 * @return array
	 */
	private function format_hub_config_to_save( array $api_config ): array {
		$api_config_array           = json_decode( $api_config['config'], true );
		$api_config_array['hub_id'] = $api_config['id'];
		// Sanitize data.
		$api_config_array['name']         = sanitize_text_field( $api_config['name'] );
		$api_config_array['description']  = ! isset( $api_config['description'] ) || ! is_string( $api_config['description'] )
			? ''
			: sanitize_textarea_field( $api_config['description'] );
		$api_config_array['immortal']     = $api_config_array['immortal'] ?? false;
		$api_config_array['is_removable'] = $api_config['is_removable'] ?? true;

		unset( $api_config_array['labels'] );

		return $api_config_array;
	}

	/**
	 * Delete config cache and create a new cache.
	 *
	 * @param  Backup_Settings $service  The backup settings service.
	 *
	 * @return mixed|array
	 */
	public static function get_fresh_frontend_configs( Backup_Settings $service ) {
		delete_site_transient( self::CONFIGS_TRANSIENT_KEY );

		$configs = self::get_configs( $service );

		foreach ( $configs as $key => &$config ) {
			$config['key'] = $key;
			unset( $config['configs'] );
		}

		return $configs;
	}

	/**
	 * Set a flag to clear active tag.
	 *
	 * @return void
	 */
	public static function set_clear_active_flag(): void {
		$value = get_site_option( self::ACTIVE_FLAG_CLEAR_KEY, 'cleared' );

		if ( 'clear' !== $value ) {
			update_site_option( self::ACTIVE_FLAG_CLEAR_KEY, 'clear' );
		}
	}

	/**
	 * Check active flag need to remove or not.
	 *
	 * @return bool
	 */
	public static function check_remove_active_flag(): bool {
		$value = get_site_option( self::ACTIVE_FLAG_CLEAR_KEY, 'cleared' );

		if ( 'clear' === $value ) {
			update_site_option( self::ACTIVE_FLAG_CLEAR_KEY, 'cleared' );

			return true;
		}

		return false;
	}

	/**
	 * Updates the active configuration from the given hub ID.
	 *
	 * @param  int $hub_id  The hub ID of the configuration to activate.
	 *
	 * @return void
	 */
	public static function active_config_from_hub_id( int $hub_id ): void {
		$config_component = wd_di()->get( Backup_Settings::class );
		$configs          = $config_component->get_configs();

		foreach ( $configs as $key => $config ) {
			$need_update = false;
			// Remove previous active status.
			if ( isset( $config['is_active'] ) && $config['is_active'] ) {
				$config['is_active'] = false;
				$need_update         = true;
			}
			// Add current active status.
			if ( isset( $config['hub_id'] ) && (int) $config['hub_id'] === $hub_id ) {
				$config['is_active'] = true;
				$need_update         = true;
			}

			if ( $need_update ) {
				update_site_option( $key, $config );
			}
		}
		// Clear cache to reflect in frontend.
		delete_site_transient( self::CONFIGS_TRANSIENT_KEY );
	}
}
