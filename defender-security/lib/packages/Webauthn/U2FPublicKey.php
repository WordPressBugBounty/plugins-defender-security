<?php

namespace WP_DEFENDER_VENDOR\Webauthn;

use WP_DEFENDER_VENDOR\CBOR\ByteStringObject;
use WP_DEFENDER_VENDOR\CBOR\MapItem;
use WP_DEFENDER_VENDOR\CBOR\MapObject;
use WP_DEFENDER_VENDOR\CBOR\NegativeIntegerObject;
use WP_DEFENDER_VENDOR\CBOR\UnsignedIntegerObject;

class U2FPublicKey
{
    public static function isU2FKey($publicKey): bool
    {
        return $publicKey[0] === "\x04";
    }

    public static function createCOSEKey($publicKey): string
    {

        $mapObject = new MapObject([
            1 => MapItem::create(
                new UnsignedIntegerObject(1, null),
                new UnsignedIntegerObject(2, null)
            ),
            3 => MapItem::create(
                new UnsignedIntegerObject(3, null),
                new NegativeIntegerObject(6, null)
            ),
            -1 => MapItem::create(
                new NegativeIntegerObject(0, null),
                new UnsignedIntegerObject(1, null)
            ),
            -2 => MapItem::create(
                new NegativeIntegerObject(1, null),
                new ByteStringObject(substr($publicKey, 1, 32))
            ),
            -3 => MapItem::create(
                new NegativeIntegerObject(2, null),
                new ByteStringObject(substr($publicKey, 33))
            ),
        ]);

        return $mapObject->__toString();
    }
}
