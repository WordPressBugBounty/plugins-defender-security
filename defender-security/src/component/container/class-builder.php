<?php
/**
 * Dependency injection container object builder.
 *
 * @package WP_Defender\Component\Container
 */

namespace WP_Defender\Component\Container;

use Throwable;
use ReflectionClass;
use RuntimeException;
use WP_Defender\Component\Container;

/**
 * Constructs objects requested by the container.
 *
 * @internal
 */
final class Builder {

	/**
	 * Entries currently being resolved.
	 *
	 * @var array<string, true>
	 */
	private array $resolving = array();

	/**
	 * Constructor parameter resolver.
	 *
	 * @var Parameter_Resolver
	 */
	private Parameter_Resolver $parameter_resolver;

	/**
	 * Initialize the builder.
	 *
	 * @param Container $container Dependency injection container.
	 */
	public function __construct( Container $container ) {
		$this->parameter_resolver = new Parameter_Resolver( $container );
	}

	/**
	 * Construct a class with named overrides and autowired dependencies.
	 *
	 * @param string               $id Class name.
	 * @param array<string, mixed> $parameters Named constructor parameters.
	 *
	 * @throws RuntimeException Entry does not exist or cannot be resolved.
	 */
	public function build( string $id, array $parameters = array() ): object {
		if ( ! $this->type_exists( $id ) ) {
			throw new RuntimeException( 'Container entry was not found.' );
		}

		if ( isset( $this->resolving[ $id ] ) ) {
			throw new RuntimeException( 'Circular dependency detected.' );
		}

		$this->resolving[ $id ] = true;

		try {
			$reflection = new ReflectionClass( $id );
			if ( ! $reflection->isInstantiable() ) {
				throw new RuntimeException( 'Container entry is not instantiable.' );
			}

			$constructor = $reflection->getConstructor();
			if ( null === $constructor ) {
				return $reflection->newInstance();
			}

			$arguments = array();
			foreach ( $constructor->getParameters() as $parameter ) {
				$arguments[] = $this->parameter_resolver->resolve( $parameter, $parameters );
			}

			return $reflection->newInstanceArgs( $arguments );
		} catch ( RuntimeException $exception ) {
			// This exception is rethrown, not rendered as output.
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
			throw $exception;
		} catch ( Throwable $exception ) {
			throw new RuntimeException( esc_html( sprintf( 'Unable to resolve container entry "%s".', $id ) ), 0, $exception );
		} finally {
			unset( $this->resolving[ $id ] );
		}
	}

	/**
	 * Determine whether a PHP type exists.
	 *
	 * @param string $id Type name.
	 */
	private function type_exists( string $id ): bool {
		return class_exists( $id ) || interface_exists( $id ) || trait_exists( $id );
	}
}
