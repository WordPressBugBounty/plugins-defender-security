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

namespace WP_DEFENDER_VENDOR\Webauthn\MetadataService;

use function WP_DEFENDER_VENDOR\Safe\base64_decode;
use function WP_DEFENDER_VENDOR\Safe\json_decode;

class SingleMetadata
{
    /**
     * @var MetadataStatement
     */
    private $statement;
    /**
     * @var string
     */
    private $data;
    /**
     * @var bool
     */
    private $isBase64Encoded;

    public function __construct(string $data, bool $isBase64Encoded)
    {
        $this->data = $data;
        $this->isBase64Encoded = $isBase64Encoded;
    }

    public function getMetadataStatement(): MetadataStatement
    {
        if (null === $this->statement) {
            $json = $this->data;
            if ($this->isBase64Encoded) {
                $json = base64_decode($this->data, true);
            }
            $statement = json_decode($json, true);
            $this->statement = MetadataStatement::createFromArray($statement);
        }

        return $this->statement;
    }
}
