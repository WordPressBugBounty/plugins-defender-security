<?php
/*
 * This file is part of the PHPASN1 library.
 *
 * Copyright © Friedrich Große <friedrich.grosse@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace WP_DEFENDER_VENDOR\FG\X509;

use WP_DEFENDER_VENDOR\FG\ASN1\OID;
use WP_DEFENDER_VENDOR\FG\ASN1\Universal\NullObject;
use WP_DEFENDER_VENDOR\FG\ASN1\Universal\Sequence;
use WP_DEFENDER_VENDOR\FG\ASN1\Universal\BitString;
use WP_DEFENDER_VENDOR\FG\ASN1\Universal\ObjectIdentifier;

class PrivateKey extends Sequence
{
    /**
     * @param string $hexKey
     * @param \WP_DEFENDER_VENDOR\FG\ASN1\ASNObject|string $algorithmIdentifierString
     */
    public function __construct($hexKey, $algorithmIdentifierString = OID::RSA_ENCRYPTION)
    {
        parent::__construct(
            new Sequence(
                new ObjectIdentifier($algorithmIdentifierString),
                new NullObject()
            ),
            new BitString($hexKey)
        );
    }
}
