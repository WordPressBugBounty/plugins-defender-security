<?php

namespace WP_DEFENDER_VENDOR\Safe;

use WP_DEFENDER_VENDOR\Safe\Exceptions\RpminfoException;

/**
 * Add an additional retrieved tag in subsequent queries.
 *
 * @param int $tag One of RPMTAG_* constant, see the rpminfo constants page.
 * @throws RpminfoException
 *
 */
function rpmaddtag(int $tag): void
{
    error_clear_last();
    $result = \rpmaddtag($tag);
    if ($result === false) {
        throw RpminfoException::createFromPhpError();
    }
}
