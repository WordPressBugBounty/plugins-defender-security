<?php
/**
 * Array utility methods.
 *
 * @since   5.4.0
 * @package WP_Defender
 */

namespace WP_Defender\Traits;

/**
 * Trait for array utility methods.
 */
trait Array_Utils {

	/**
	 * Deep comparison of two arrays that can handle nested arrays and objects.
	 *
	 * @param  mixed $old_data  Old data to compare.
	 * @param  mixed $new_data  New data to compare.
	 *
	 * @return bool True if arrays differ, false if they are the same.
	 */
	protected function arrays_differ_deeply( $old_data, $new_data ) {
		// If types are different, they differ.
		if ( gettype( $old_data ) !== gettype( $new_data ) ) {
			return true;
		}

		// Handle non-array types.
		if ( ! is_array( $old_data ) ) {
			return $old_data !== $new_data;
		}

		// Handle arrays - normalize and compare.
		$old_normalized = $this->normalize_array( $old_data );
		$new_normalized = $this->normalize_array( $new_data );

		// Compare array sizes first.
		if ( count( $old_normalized ) !== count( $new_normalized ) ) {
			return true;
		}

		// Compare each key-value pair.
		foreach ( $old_normalized as $key => $value ) {
			if ( ! array_key_exists( $key, $new_normalized ) ) {
				return true;
			}

			if ( $this->arrays_differ_deeply( $value, $new_normalized[ $key ] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Normalize array for comparison by sorting arrays and handling special cases.
	 *
	 * @param  array $data_array  Array to normalize.
	 *
	 * @return array Normalized array.
	 */
	protected function normalize_array( $data_array ) {
		if ( ! is_array( $data_array ) ) {
			return $data_array;
		}

		$normalized = array();

		foreach ( $data_array as $key => $value ) {
			if ( is_array( $value ) ) {
				// For indexed arrays (like preset values), sort to handle order differences.
				if ( array_keys( $value ) === range( 0, count( $value ) - 1 ) ) {
					sort( $value );
				}
				$normalized[ $key ] = $this->normalize_array( $value );
			} else {
				$normalized[ $key ] = $value;
			}
		}

		// Sort associative arrays by key for consistent comparison.
		if ( ! empty( $normalized ) ) {
			ksort( $normalized );
		}

		return $normalized;
	}
}
