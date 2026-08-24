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

namespace WP_DEFENDER_VENDOR\Cose\Algorithm\Mac;

use WP_DEFENDER_VENDOR\Cose\Algorithm\Algorithm;
use WP_DEFENDER_VENDOR\Cose\Key\Key;

interface Mac extends Algorithm
{
    public function hash(string $data, Key $key): string;

    public function verify(string $data, Key $key, string $signature): bool;
}
