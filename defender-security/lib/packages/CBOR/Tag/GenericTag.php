<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace WP_DEFENDER_VENDOR\CBOR\Tag;

use WP_DEFENDER_VENDOR\CBOR\CBORObject;
use WP_DEFENDER_VENDOR\CBOR\Tag;

final class GenericTag extends Tag
{
    public static function getTagId(): int
    {
        return -1;
    }

    public static function createFromLoadedData(int $additionalInformation, ?string $data, CBORObject $object): Tag
    {
        return new self($additionalInformation, $data, $object);
    }

    /**
     * @deprecated The method will be removed on v3.0. Please rely on the WP_DEFENDER_VENDOR\CBOR\Normalizable interface
     */
    public function getNormalizedData(bool $ignoreTags = false)
    {
        return $this->object;
    }
}
