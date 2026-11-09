<?php

namespace WP_Defender\Extra;
/*
 * ip_in_range.php - Function to determine if an IP is located in a
 *                   specific range as specified via several alternative
 *                   formats.
 *
 * Network ranges can be specified as:
 * 1. Wildcard format:     1.2.3.*
 * 2. CIDR format:         1.2.3/24  OR  1.2.3.4/255.255.255.0
 * 3. Start-End IP format: 1.2.3.0-1.2.3.255
 *
 * Return value BOOLEAN : ip_in_range($ip, $range);
 *
 * Copyright 2008: Paul Gregg <pgregg@pgregg.com>
 * 10 January 2008
 * Version: 1.2
 *
 * Source website: http://www.pgregg.com/projects/php/ip_in_range/
 * Version 1.2
 *
 * This software is Donationware - if you feel you have benefited from
 * the use of this tool then please consider a donation. The value of
 * which is entirely left up to your discretion.
 * http://www.pgregg.com/donate/
 *
 * Please do not remove this header, or source attibution from this file.
 */

/*
* Modified by James Greene <james@cloudflare.com> to include IPV6 support
* (original version only supported IPV4).
* 21 May 2012
*/

class IP_Helper {
	// decbin32
// In order to simplify working with IP addresses (in binary) and their
// netmasks, it is easier to ensure that the binary strings are padded
// with zeros out to 32 characters - IP addresses are 32 bit numbers
	function decbin32( $dec ) {
		return str_pad( decbin( (int) $dec ), 32, '0', STR_PAD_LEFT );
	}

	/**
	 * Determine if an IPv4 address is within a specified range.
	 *
	 * Supports:
	 * - Wildcard format:     1.2.3.* or 1.2.*.*
	 * - CIDR format:         1.2.3/24, 1.2.3.4/24 or 1.2.3.4/255.255.255.0
	 * - Start-End IP format: 1.2.3.0-1.2.3.255
	 * - Exact IP format:     1.2.3.4
	 *
	 * Rejects invalid addresses, prefixes outside 0-32, noncontiguous dotted masks, and reversed ranges.
	 *
	 * @param string $ip    IPv4 address to test.
	 * @param string $range IPv4 range expression.
	 *
	 * @return bool True if $ip is within $range, false otherwise.
	 */
	function ipv4_in_range( $ip, $range ) {
		if ( ! is_string( $ip ) || ! is_string( $range ) || '' === trim( $ip ) || '' === trim( $range ) ) {
			return false;
		}

		$ip    = trim( $ip );
		$range = trim( $range );

		// Validate target IP as a valid IPv4 address.
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return false;
		}

		$ip_long = ip2long( $ip );
		$ip_dec  = (float) sprintf( '%u', $ip_long );

		if ( strpos( $range, '/' ) !== false ) {
			if ( substr_count( $range, '/' ) !== 1 ) {
				return false;
			}

			list( $range_ip, $netmask ) = explode( '/', $range, 2 );
			$range_ip = trim( $range_ip );
			$netmask  = trim( $netmask );

			if ( strpos( $netmask, '.' ) !== false ) {
				// Dotted netmask format: e.g. 1.2.3.4/255.255.255.0
				if ( false === filter_var( $netmask, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					return false;
				}
				if ( false === filter_var( $range_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					return false;
				}

				$netmask_long = ip2long( $netmask );
				// Ensure the netmask is contiguous (1s followed by 0s in 32-bit binary).
				$bin_mask = sprintf( '%032b', $netmask_long );
				if ( ! preg_match( '/^1*0*$/', $bin_mask ) ) {
					return false;
				}

				$range_long = ip2long( $range_ip );

				return ( ( $ip_long & $netmask_long ) === ( $range_long & $netmask_long ) );
			} else {
				// CIDR prefix format: e.g. 1.2.3/24 or 1.2.3.4/24
				if ( ! preg_match( '/^\d+$/', $netmask ) ) {
					return false;
				}

				$prefix = (int) $netmask;
				if ( $prefix < 0 || $prefix > 32 ) {
					return false;
				}

				// Shorthand support: pad shorthand octets (e.g. 1.2.3 -> 1.2.3.0).
				$normalized_range_ip = implode( '.', array_pad( explode( '.', $range_ip ), 4, '0' ) );
				if ( false === filter_var( $normalized_range_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					return false;
				}

				if ( 0 === $prefix ) {
					return true;
				}

				$range_long = ip2long( $normalized_range_ip );

				$netmask_long = ( ~0 << ( 32 - $prefix ) ) & 0xFFFFFFFF;

				return ( ( $ip_long & $netmask_long ) === ( $range_long & $netmask_long ) );
			}
		}

		if ( strpos( $range, '*' ) !== false ) {
			// Wildcard format: 1.2.3.* or 1.2.*.*
			$octets = explode( '.', $range );
			if ( 4 !== count( $octets ) ) {
				return false;
			}

			$seen_wildcard = false;
			$lower_parts   = array();
			$upper_parts   = array();

			foreach ( $octets as $part ) {
				$part = trim( $part );
				if ( '*' === $part ) {
					$seen_wildcard = true;
					$lower_parts[] = '0';
					$upper_parts[] = '255';
				} else {
					if ( $seen_wildcard ) {
						// Wildcards must be trailing; e.g. 1.*.3.* is invalid.
						return false;
					}
					if ( ! preg_match( '/^(?:0|[1-9]\d*)$/', $part ) || (int) $part < 0 || (int) $part > 255 ) {
						return false;
					}
					$lower_parts[] = $part;
					$upper_parts[] = $part;
				}
			}

			$lower_ip = implode( '.', $lower_parts );
			$upper_ip = implode( '.', $upper_parts );

			if ( false === filter_var( $lower_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ||
			     false === filter_var( $upper_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return false;
			}

			$lower_long = ip2long( $lower_ip );
			$upper_long = ip2long( $upper_ip );

			$lower_dec = (float) sprintf( '%u', $lower_long );
			$upper_dec = (float) sprintf( '%u', $upper_long );

			return ( $ip_dec >= $lower_dec && $ip_dec <= $upper_dec );
		}

		if ( strpos( $range, '-' ) !== false ) {
			// Start-End format: 1.2.3.0-1.2.3.255
			if ( substr_count( $range, '-' ) !== 1 ) {
				return false;
			}

			list( $lower, $upper ) = explode( '-', $range, 2 );
			$lower = trim( $lower );
			$upper = trim( $upper );

			if ( false === filter_var( $lower, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ||
			     false === filter_var( $upper, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return false;
			}

			$lower_dec = (float) sprintf( '%u', ip2long( $lower ) );
			$upper_dec = (float) sprintf( '%u', ip2long( $upper ) );

			return ( $ip_dec >= $lower_dec && $ip_dec <= $upper_dec );
		}

		// Single IP exact match.
		return $ip === $range;
	}

	/**
	 * Convert IPv6 address to an exact decimal string representation without floating-point precision loss.
	 *
	 * @deprecated Use inet_pton() binary comparisons directly.
	 *
	 * @param string $ip IPv6 address string.
	 *
	 * @return string|false Decimal string, or false on failure.
	 */
	function ip2long6( $ip ) {
		$bin = $this->ipv6_to_binary( $ip );
		if ( false === $bin ) {
			return false;
		}

		$digits = array( 0 );
		for ( $i = 0; $i < 16; $i++ ) {
			$carry = ord( $bin[ $i ] );
			$count = count( $digits );
			for ( $j = 0; $j < $count; $j++ ) {
				$val          = $digits[ $j ] * 256 + $carry;
				$digits[ $j ] = $val % 10;
				$carry        = intdiv( $val, 10 );
			}
			while ( $carry > 0 ) {
				$digits[] = $carry % 10;
				$carry    = intdiv( $carry, 10 );
			}
		}

		return implode( '', array_reverse( $digits ) );
	}

	/**
	 * Get the IPv6 full format and return it as a decimal string value.
	 *
	 * @deprecated Use inet_pton() binary comparisons directly.
	 *
	 * @param string $ip IPv6 address string (may include CIDR suffix).
	 *
	 * @return string|false Decimal string representation of the IP, or false on failure.
	 */
	function get_ipv6_full( $ip ) {
		if ( ! is_string( $ip ) ) {
			return false;
		}

		$pieces = explode( '/', $ip, 2 );

		return $this->ip2long6( $pieces[0] );
	}

	/**
	 * Convert an IPv6 string to 16-byte binary string.
	 *
	 * @param string $ip IPv6 address string.
	 *
	 * @return string|false 16-byte binary string or false on failure.
	 */
	private function ipv6_to_binary( $ip ) {
		if ( ! is_string( $ip ) || '' === $ip ) {
			return false;
		}

		$bin = @inet_pton( trim( $ip ) );
		if ( false === $bin || 16 !== strlen( $bin ) ) {
			return false;
		}

		return $bin;
	}

	/**
	 * Determine whether an IPv6 address is within a specified IPv6 CIDR range or matches an IPv6 address.
	 *
	 * Uses inet_pton() binary comparisons with exact bitmasking for split-byte prefixes.
	 *
	 * @param string $ip       The IPv6 address to test.
	 * @param string $range_ip The IPv6 address or CIDR range (e.g. 2001:db8::/32 or 2001:db8::1).
	 *
	 * @return bool True if $ip is within $range_ip, false otherwise.
	 */
	function ipv6_in_range( $ip, $range_ip ) {
		if ( ! is_string( $ip ) || ! is_string( $range_ip ) || '' === trim( $ip ) || '' === trim( $range_ip ) ) {
			return false;
		}

		$ip       = trim( $ip );
		$range_ip = trim( $range_ip );

		if ( strpos( $range_ip, '/' ) !== false ) {
			if ( substr_count( $range_ip, '/' ) !== 1 ) {
				return false;
			}

			list( $base_ip, $prefix_str ) = explode( '/', $range_ip, 2 );
			$base_ip    = trim( $base_ip );
			$prefix_str = trim( $prefix_str );

			if ( ! preg_match( '/^\d+$/', $prefix_str ) ) {
				return false;
			}

			$prefix = (int) $prefix_str;
			if ( $prefix < 0 || $prefix > 128 ) {
				return false;
			}
		} else {
			$base_ip = $range_ip;
			$prefix  = 128;
		}

		$ip_bin   = $this->ipv6_to_binary( $ip );
		$base_bin = $this->ipv6_to_binary( $base_ip );

		// Reject invalid IP strings, non-IPv6 addresses, or cross-family checks.
		if ( false === $ip_bin || false === $base_bin ) {
			return false;
		}

		$full_bytes = intdiv( $prefix, 8 );
		$rem_bits   = $prefix % 8;

		if ( substr( $ip_bin, 0, $full_bytes ) !== substr( $base_bin, 0, $full_bytes ) ) {
			return false;
		}

		if ( $rem_bits > 0 ) {
			$mask = ( 0xFF << ( 8 - $rem_bits ) ) & 0xFF;
			if ( ( ord( $ip_bin[ $full_bytes ] ) & $mask ) !== ( ord( $base_bin[ $full_bytes ] ) & $mask ) ) {
				return false;
			}
		}

		return true;
	}
}
