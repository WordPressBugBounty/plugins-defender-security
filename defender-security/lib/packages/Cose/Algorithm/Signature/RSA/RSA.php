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

namespace WP_DEFENDER_VENDOR\Cose\Algorithm\Signature\RSA;

use WP_DEFENDER_VENDOR\Assert\Assertion;
use WP_DEFENDER_VENDOR\Cose\Algorithm\Signature\Signature;
use WP_DEFENDER_VENDOR\Cose\Key\Key;
use WP_DEFENDER_VENDOR\Cose\Key\RsaKey;
use InvalidArgumentException;

abstract class RSA implements Signature
{
    public function sign(string $data, Key $key): string
    {
        $key = $this->handleKey($key);
        Assertion::true($key->isPrivate(), 'The key is not private');

        if (false === openssl_sign($data, $signature, $key->asPem(), $this->getHashAlgorithm())) {
            throw new InvalidArgumentException('Unable to sign the data');
        }

        return $signature;
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);

        return 1 === openssl_verify($data, $signature, $key->asPem(), $this->getHashAlgorithm());
    }

    abstract protected function getHashAlgorithm(): int;

    private function handleKey(Key $key): RsaKey
    {
        return new RsaKey($key->getData());
    }
}
