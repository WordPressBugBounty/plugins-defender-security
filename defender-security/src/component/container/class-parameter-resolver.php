<?php
/**
 * Dependency injection container parameter resolver.
 *
 * @package WP_Defender\Component\Container
 */

namespace WP_Defender\Component\Container;

use RuntimeException;
use ReflectionParameter;
use ReflectionUnionType;
use ReflectionNamedType;
use WP_Defender\Component\Container;

/**
 * Resolves constructor parameters through the container.
 *
 * @internal
 */
final class Parameter_Resolver {

	/**
	 * Dependency injection container.
	 *
	 * @var Container
	 */
	private Container $container;

	/**
	 * Initialize the parameter resolver.
	 *
	 * @param Container $container Dependency injection container.
	 */
	public function __construct( Container $container ) {
		$this->container = $container;
	}

	/**
	 * Resolve one constructor parameter.
	 *
	 * @param ReflectionParameter  $parameter Constructor parameter.
	 * @param array<string, mixed> $parameters Named constructor parameters.
	 *
	 * @throws RuntimeException Parameter cannot be resolved.
	 */
	public function resolve( ReflectionParameter $parameter, array $parameters ): mixed {
		$name = $parameter->getName();
		if ( array_key_exists( $name, $parameters ) ) {
			return $parameters[ $name ];
		}

		$type       = $parameter->getType();
		$dependency = $this->resolve_dependency( $type );
		if ( null !== $dependency ) {
			return $dependency;
		}

		if ( $parameter->isDefaultValueAvailable() ) {
			return $parameter->getDefaultValue();
		}

		if ( null !== $type && $parameter->allowsNull() ) {
			return null;
		}

		$declaring_class = $parameter->getDeclaringClass();
		$class_name      = $declaring_class ? $declaring_class->getName() : 'unknown';

		throw new RuntimeException( esc_html( sprintf( 'Unable to resolve parameter "$%s" for class "%s".', $name, $class_name ) ) );
	}

	/**
	 * Resolve a dependency from a reflected parameter type.
	 *
	 * @param mixed $type Reflected parameter type.
	 */
	private function resolve_dependency( mixed $type ): mixed {
		if ( $type instanceof ReflectionNamedType ) {
			return $this->resolve_named_type( $type );
		}

		if ( $type instanceof ReflectionUnionType ) {
			foreach ( $type->getTypes() as $named_type ) {
				$dependency = $this->resolve_named_type( $named_type );
				if ( null !== $dependency ) {
					return $dependency;
				}
			}
		}

		return null;
	}

	/**
	 * Resolve a named, non-built-in dependency type.
	 *
	 * @param ReflectionNamedType $type Reflected parameter type.
	 */
	private function resolve_named_type( ReflectionNamedType $type ): mixed {
		if ( $type->isBuiltin() || ! $this->container->has( $type->getName() ) ) {
			return null;
		}

		return $this->container->get( $type->getName() );
	}
}
