<?php
/*
 * This file is part of the PHPASN1 library.
 *
 * Copyright © Friedrich Große <friedrich.grosse@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace WP_DEFENDER_VENDOR\FG\ASN1\Universal;

use WP_DEFENDER_VENDOR\FG\ASN1\AbstractString;
use WP_DEFENDER_VENDOR\FG\ASN1\Identifier;

class CharacterString extends AbstractString
{
    public function __construct($string)
    {
        $this->value = $string;
        $this->allowAll();
    }

    public function getType()
    {
        return Identifier::CHARACTER_STRING;
    }
}
