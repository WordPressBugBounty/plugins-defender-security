<?php
/**
 * Dependency injection container.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use ReflectionClass;
use RuntimeException;
use WP_Defender\Component\Container\Builder;

/**
 * Lightweight dependency injection container with constructor autowiring.
 */
class Container {

	/**
	 * Resolved and explicitly registered entries.
	 *
	 * @var array<string, mixed>
	 */
	private array $entries = array();

	/**
	 * Class instance builder.
	 *
	 * @var Builder
	 */
	private Builder $builder;

	/**
	 * Register the container itself.
	 */
	public function __construct() {
		$this->entries[ self::class ] = $this;
		$this->builder                = new Builder( $this );
	}

	/**
	 * Find an entry or construct and share a class.
	 *
	 * @template       T of object
	 * @param string $id Entry identifier or class name.
	 *
	 * @return         mixed
	 * @phpstan-param  class-string<T> $id
	 * @phpstan-return T
	 *
	 * @throws RuntimeException Entry does not exist or cannot be resolved.
	 */
	public function get( string $id ): mixed {
		if ( array_key_exists( $id, $this->entries ) ) {
			return $this->entries[ $id ];
		}

		$entry                = $this->builder->build( $id );
		$this->entries[ $id ] = $entry;

		return $entry;
	}

	/**
	 * Register or replace an entry.
	 *
	 * @param string $id Entry identifier.
	 * @param mixed  $value Entry value.
	 */
	public function set( string $id, mixed $value ): void {
		$this->entries[ $id ] = $value;
	}

	/**
	 * Construct a fresh class instance.
	 *
	 * @template       T of object
	 * @param string              $id Class name.
	 * @param array<string,mixed> $parameters Named constructor parameters.
	 *
	 * @return         object
	 * @phpstan-param  class-string<T> $id
	 * @phpstan-return T
	 *
	 * @throws RuntimeException Entry does not exist or cannot be resolved.
	 */
	public function make( string $id, array $parameters = array() ): object {
		return $this->builder->build( $id, $parameters );
	}

	/**
	 * Determine whether an entry is registered or can be instantiated.
	 *
	 * This check does not construct the entry.
	 *
	 * @param string $id Entry identifier or class name.
	 */
	public function has( string $id ): bool {
		return array_key_exists( $id, $this->entries ) || $this->is_instantiable( $id );
	}

	/**
	 * Determine whether a class can be instantiated.
	 *
	 * @param string $id Class name.
	 */
	private function is_instantiable( string $id ): bool {
		return class_exists( $id ) && ( new ReflectionClass( $id ) )->isInstantiable();
	}
}
