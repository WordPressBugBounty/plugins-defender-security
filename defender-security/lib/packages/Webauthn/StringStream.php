<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace WP_DEFENDER_VENDOR\Webauthn;

use WP_DEFENDER_VENDOR\Assert\Assertion;
use WP_DEFENDER_VENDOR\CBOR\Stream;
use function WP_DEFENDER_VENDOR\Safe\fclose;
use function WP_DEFENDER_VENDOR\Safe\fopen;
use function WP_DEFENDER_VENDOR\Safe\fread;
use function WP_DEFENDER_VENDOR\Safe\fwrite;
use function WP_DEFENDER_VENDOR\Safe\rewind;
use function WP_DEFENDER_VENDOR\Safe\sprintf;

final class StringStream implements Stream
{
    /**
     * @var resource
     */
    private $data;

    /**
     * @var int
     */
    private $length;

    /**
     * @var int
     */
    private $totalRead = 0;

    public function __construct(string $data)
    {
        $this->length = mb_strlen($data, '8bit');
        $resource = fopen('php://memory', 'rb+');
        fwrite($resource, $data);
        rewind($resource);
        $this->data = $resource;
    }

    public function read(int $length): string
    {
        if (0 === $length) {
            return '';
        }
        $read = fread($this->data, $length);
        $bytesRead = mb_strlen($read, '8bit');
        Assertion::length($read, $length, sprintf('Out of range. Expected: %d, read: %d.', $length, $bytesRead), null, '8bit');
        $this->totalRead += $bytesRead;

        return $read;
    }

    public function close(): void
    {
        fclose($this->data);
    }

    public function isEOF(): bool
    {
        return $this->totalRead === $this->length;
    }
}
