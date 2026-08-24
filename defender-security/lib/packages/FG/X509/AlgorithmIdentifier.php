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

use WP_DEFENDER_VENDOR\FG\ASN1\Universal\NullObject;
use WP_DEFENDER_VENDOR\FG\ASN1\Composite\AttributeTypeAndValue;

class AlgorithmIdentifier extends AttributeTypeAndValue
{
    public function __construct($objectIdentifierString)
    {
        parent::__construct($objectIdentifierString, new NullObject());
    }
}
