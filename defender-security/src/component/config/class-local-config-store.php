<?php
/**
 * Local Config Store for Configs UI (Smush-style single option storage).
 *
 * @package WP_Defender\Component\Config
 */

namespace WP_Defender\Component\Config;

use WP_Defender\Component\Backup_Settings;

/**
 * Handles Configs persistence in a single option key.
 */
class Local_Config_Store {

	/**
	 * Local option key for all configs.
	 */
	public const OPTION_KEY = 'wp-defender-preset_configs';

	/**
	 * Backup settings service.
	 *
	 * @var Backup_Settings
	 */
	private $service;

	/**
	 * Constructor.
	 *
	 * @param  Backup_Settings $service  Backup settings service.
	 */
	public function __construct( Backup_Settings $service ) {
		$this->service = $service;
	}

	/**
	 * Gets all locally stored configs.
	 *
	 * @return array
	 */
	public function get_all(): array {
		$this->maybe_initialize_from_legacy();
		$configs = get_site_option( self::OPTION_KEY, array() );

		return is_array( $configs ) ? $configs : array();
	}

	/**
	 * Gets one config by key.
	 *
	 * @param  string $key  Config key.
	 *
	 * @return array|null
	 */
	public function get_one( string $key ): ?array {
		$configs = $this->get_all();
		$key     = trim( $key );

		if ( '' === $key || ! isset( $configs[ $key ] ) || ! is_array( $configs[ $key ] ) ) {
			return null;
		}

		return $configs[ $key ];
	}

	/**
	 * Persists full configs map.
	 *
	 * @param  array $configs  Configs map keyed by config key.
	 *
	 * @return void
	 */
	public function save_all( array $configs ): void {
		update_site_option( self::OPTION_KEY, $configs );
	}

	/**
	 * Creates a config from current Defender settings.
	 *
	 * @param  string $name             Config name.
	 * @param  string $description      Config description.
	 * @param  string $note_added_time  Note timestamp.
	 *
	 * @return array
	 */
	public function create_from_current( string $name, string $description = '', string $note_added_time = '' ): array {
		$configs  = $this->get_all();
		$key      = $this->generate_key( 'wp_defender_config' );
		$settings = $this->service->parse_data_for_import();

		$data = array_merge(
			array(
				'key'             => $key,
				'name'            => sanitize_text_field( $name ),
				'description'     => sanitize_textarea_field( $description ),
				'note_added_time' => sanitize_text_field( $note_added_time ),
				'immortal'        => false,
				'is_removable'    => true,
				'is_active'       => false,
				'date'            => (string) time(),
			),
			$settings
		);

		unset( $data['labels'] );

		$configs[ $key ] = $data;
		$this->save_all( $configs );

		return $data;
	}

	/**
	 * Adds imported config.
	 *
	 * @param  array $importer  Imported config payload.
	 *
	 * @return array
	 */
	public function add_imported( array $importer ): array {
		$configs = $this->get_all();
		$key     = $this->generate_key( 'wp_defender_config_import' );

		$data = array(
			'key'             => $key,
			'name'            => sanitize_text_field( (string) ( $importer['name'] ?? '' ) ),
			'description'     => isset( $importer['description'] ) ? sanitize_textarea_field( (string) $importer['description'] ) : '',
			'note_added_time' => isset( $importer['note_added_time'] ) ? sanitize_text_field( (string) $importer['note_added_time'] ) : '',
			'immortal'        => false,
			'is_removable'    => true,
			'is_active'       => false,
			'date'            => (string) time(),
			'configs'         => $importer['configs'],
			'strings'         => $this->service->import_module_strings( $importer ),
		);

		$configs[ $key ] = $data;
		$this->save_all( $configs );

		return $data;
	}

	/**
	 * Updates config metadata.
	 *
	 * @param  string      $key             Config key.
	 * @param  string|null $name            Name.
	 * @param  string|null $description     Description.
	 * @param  string|null $note_added_time Note timestamp.
	 *
	 * @return bool
	 */
	public function update_metadata( string $key, ?string $name, ?string $description, ?string $note_added_time ): bool {
		$configs = $this->get_all();
		if ( ! isset( $configs[ $key ] ) || ! is_array( $configs[ $key ] ) ) {
			return false;
		}

		if ( null !== $name && '' !== trim( $name ) ) {
			$configs[ $key ]['name'] = sanitize_text_field( $name );
		}
		if ( null !== $description ) {
			$configs[ $key ]['description'] = sanitize_textarea_field( $description );
		}
		if ( null !== $note_added_time ) {
			$configs[ $key ]['note_added_time'] = sanitize_text_field( $note_added_time );
		}

		$this->save_all( $configs );

		return true;
	}

	/**
	 * Applies a config by key.
	 *
	 * @param  string $key  Config key.
	 *
	 * @return array|null
	 */
	public function apply( string $key ): ?array {
		$configs = $this->get_all();
		if ( ! isset( $configs[ $key ] ) || ! is_array( $configs[ $key ] ) ) {
			return null;
		}

		$config = $configs[ $key ];
		if ( ! isset( $config['configs'] ) || ! is_array( $config['configs'] ) ) {
			return null;
		}

		foreach ( $configs as $config_key => &$value ) {
			if ( ! is_array( $value ) ) {
				continue;
			}
			$value['is_active'] = ( $config_key === $key );
		}
		$this->save_all( $configs );

		return $config;
	}

	/**
	 * Deletes one config by key.
	 *
	 * @param  string $key  Config key.
	 *
	 * @return bool
	 */
	public function delete_one( string $key ): bool {
		$configs = $this->get_all();
		if ( ! isset( $configs[ $key ] ) || ! is_array( $configs[ $key ] ) ) {
			return false;
		}

		$is_removable = isset( $configs[ $key ]['is_removable'] ) ? (bool) $configs[ $key ]['is_removable'] : true;
		$is_immortal  = isset( $configs[ $key ]['immortal'] ) ? (bool) $configs[ $key ]['immortal'] : false;
		if ( ! $is_removable || $is_immortal ) {
			return false;
		}

		unset( $configs[ $key ] );
		$this->save_all( $configs );

		return true;
	}

	/**
	 * Deletes all removable configs except keep keys.
	 *
	 * @param  array $keep_keys  Keys to preserve.
	 *
	 * @return void
	 */
	public function sync_keep_list( array $keep_keys ): void {
		$keep_keys = array_fill_keys( array_map( 'strval', $keep_keys ), true );
		$configs   = $this->get_all();

		foreach ( $configs as $key => $config ) {
			if ( isset( $keep_keys[ $key ] ) ) {
				continue;
			}

			$is_removable = isset( $config['is_removable'] ) ? (bool) $config['is_removable'] : true;
			$is_immortal  = isset( $config['immortal'] ) ? (bool) $config['immortal'] : false;
			if ( ! $is_removable || $is_immortal ) {
				continue;
			}

			unset( $configs[ $key ] );
		}

		$this->save_all( $configs );
	}

	/**
	 * Gets configs for frontend list response.
	 *
	 * @return array
	 */
	public function get_frontend_configs(): array {
		$configs = $this->get_all();

		foreach ( $configs as $key => &$config ) {
			if ( ! is_array( $config ) ) {
				continue;
			}
			$config['key']     = $key;
			$config['strings'] = $this->service->import_module_strings( $config );
			if ( isset( $config['configs'] ) ) {
				unset( $config['configs'] );
			}
		}

		return $configs;
	}

	/**
	 * Gets full config payload for download/apply.
	 *
	 * @param  string $key  Config key.
	 *
	 * @return array|null
	 */
	public function get_full_for_key( string $key ): ?array {
		$config = $this->get_one( $key );
		if ( null === $config ) {
			return null;
		}

		$sample = $this->service->gather_data();
		foreach ( $sample as $slug => $data ) {
			foreach ( $data as $setting_key => $val ) {
				if ( ! isset( $config['configs'][ $slug ][ $setting_key ] ) ) {
					$config['configs'][ $slug ][ $setting_key ] = null;
				}
			}
		}

		return $config;
	}

	/**
	 * Initializes local storage from legacy per-option configs if needed.
	 *
	 * @return void
	 */
	private function maybe_initialize_from_legacy(): void {
		$existing = get_site_option( self::OPTION_KEY, null );
		if ( is_array( $existing ) ) {
			return;
		}

		$legacy = $this->service->get_configs();
		if ( array() === $legacy ) {
			update_site_option( self::OPTION_KEY, array() );
			return;
		}

		foreach ( $legacy as $key => &$config ) {
			if ( ! is_array( $config ) ) {
				continue;
			}
			$config['key'] = (string) $key;
		}
		update_site_option( self::OPTION_KEY, $legacy );
	}

	/**
	 * Generates a unique config key.
	 *
	 * @param  string $prefix  Prefix.
	 *
	 * @return string
	 */
	private function generate_key( string $prefix ): string {
		return $prefix . '_' . time() . '_' . wp_rand( 1000, 9999 );
	}
}
