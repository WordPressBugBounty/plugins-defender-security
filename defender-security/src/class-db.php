<?php
/**
 * Handles database operations.
 *
 * @package WP_Defender
 */

namespace WP_Defender;

use Calotes\DB\Mapper;
use Calotes\Base\Model;
use ReflectionException;

/**
 * Contains methods for saving the current instance, getting the ORM, and retrieving the table name.
 */
class DB extends Model {

	/**
	 * Constructor for the class.
	 * Initializes the object by parsing annotations.
	 *
	 * @return void
	 */
	public function __construct() {
		$this->parse_annotations();
	}

	/**
	 * Save the current instance.
	 *
	 * @return false|int
	 */
	public function save(): bool|int {
		try {
			return self::get_orm()->save( $this );
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				$this->log(
					sprintf(
						'Failed to save %s: %s in %s:%d',
						static::class,
						$e->getMessage(),
						$e->getFile(),
						$e->getLine()
					),
					'db-save-error.log'
				);
			}

			return false;
		}
	}

	/**
	 * Retrieves the ORM instance from the dependency injection container.
	 *
	 * @return Mapper The ORM instance.
	 */
	protected static function get_orm(): Mapper {
		return wd_di()->get( Mapper::class );
	}

	/**
	 * Get table name.
	 *
	 * @return string
	 */
	public function get_table(): string {
		return $this->table;
	}
}
