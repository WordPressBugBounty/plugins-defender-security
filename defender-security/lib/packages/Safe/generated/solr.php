<?php

namespace WP_DEFENDER_VENDOR\Safe;

use WP_DEFENDER_VENDOR\Safe\Exceptions\SolrException;

/**
 * This function returns the current version of the extension as a string.
 *
 * @return string It returns a string on success.
 * @throws SolrException
 *
 */
function solr_get_version(): string
{
    error_clear_last();
    $result = \solr_get_version();
    if ($result === false) {
        throw SolrException::createFromPhpError();
    }
    return $result;
}
