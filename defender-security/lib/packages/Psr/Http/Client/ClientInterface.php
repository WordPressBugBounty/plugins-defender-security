<?php

namespace WP_DEFENDER_VENDOR\Psr\Http\Client;

use WP_DEFENDER_VENDOR\Psr\Http\Message\RequestInterface;
use WP_DEFENDER_VENDOR\Psr\Http\Message\ResponseInterface;

interface ClientInterface
{
    /**
     * Sends a PSR-7 request and returns a PSR-7 response.
     *
     * @param RequestInterface $request
     *
     * @return ResponseInterface
     *
     * @throws \WP_DEFENDER_VENDOR\Psr\Http\Client\ClientExceptionInterface If an error happens while processing the request.
     */
    public function sendRequest(RequestInterface $request): ResponseInterface;
}
