<?php

/**
 * This file is part of the ramsey/uuid library
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright Copyright (c) Ben Ramsey <ben@benramsey.com>
 * @license http://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace WP_DEFENDER_VENDOR\Ramsey\Uuid\Builder;

use WP_DEFENDER_VENDOR\Ramsey\Uuid\Codec\CodecInterface;
use WP_DEFENDER_VENDOR\Ramsey\Uuid\Converter\NumberConverterInterface;
use WP_DEFENDER_VENDOR\Ramsey\Uuid\Converter\Time\DegradedTimeConverter;
use WP_DEFENDER_VENDOR\Ramsey\Uuid\Converter\TimeConverterInterface;
use WP_DEFENDER_VENDOR\Ramsey\Uuid\DegradedUuid;
use WP_DEFENDER_VENDOR\Ramsey\Uuid\Rfc4122\Fields as Rfc4122Fields;
use WP_DEFENDER_VENDOR\Ramsey\Uuid\UuidInterface;

/**
 * @deprecated DegradedUuid instances are no longer necessary to support 32-bit systems. Please transition to {@see DefaultUuidBuilder}.
 *
 * @immutable
 */
class DegradedUuidBuilder implements UuidBuilderInterface
{
    private TimeConverterInterface $timeConverter;

    /**
     * @param NumberConverterInterface $numberConverter The number converter to use when constructing the DegradedUuid
     * @param TimeConverterInterface|null $timeConverter The time converter to use for converting timestamps extracted
     *     from a UUID to Unix timestamps
     */
    public function __construct(
        private NumberConverterInterface $numberConverter,
        ?TimeConverterInterface $timeConverter = null
    ) {
        $this->timeConverter = $timeConverter ?: new DegradedTimeConverter();
    }

    /**
     * Builds and returns a DegradedUuid
     *
     * @param CodecInterface $codec The codec to use for building this DegradedUuid instance
     * @param string $bytes The byte string from which to construct a UUID
     *
     * @return DegradedUuid The DegradedUuidBuild returns an instance of WP_DEFENDER_VENDOR\Ramsey\Uuid\DegradedUuid
     *
     * @phpstan-impure
     */
    public function build(CodecInterface $codec, string $bytes): UuidInterface
    {
        return new DegradedUuid(new Rfc4122Fields($bytes), $this->numberConverter, $codec, $this->timeConverter);
    }
}
