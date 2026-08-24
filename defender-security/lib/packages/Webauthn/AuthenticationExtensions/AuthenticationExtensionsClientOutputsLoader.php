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

namespace WP_DEFENDER_VENDOR\Webauthn\AuthenticationExtensions;

use WP_DEFENDER_VENDOR\Assert\Assertion;
use WP_DEFENDER_VENDOR\CBOR\CBORObject;
use WP_DEFENDER_VENDOR\CBOR\MapObject;

abstract class AuthenticationExtensionsClientOutputsLoader
{
    public static function load(CBORObject $object): AuthenticationExtensionsClientOutputs
    {
        Assertion::isInstanceOf($object, MapObject::class, 'Invalid extension object');
        $data = $object->getNormalizedData();
        $extensions = new AuthenticationExtensionsClientOutputs();
        foreach ($data as $key => $value) {
            Assertion::string($key, 'Invalid extension key');
            $extensions->add(new AuthenticationExtension($key, $value));
        }

        return $extensions;
    }
}
