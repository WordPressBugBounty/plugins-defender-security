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

namespace WP_DEFENDER_VENDOR\Webauthn\MetadataService;

use WP_DEFENDER_VENDOR\Assert\Assertion;
use WP_DEFENDER_VENDOR\Base64Url\Base64Url;
use WP_DEFENDER_VENDOR\Psr\Http\Client\ClientInterface;
use WP_DEFENDER_VENDOR\Psr\Http\Message\RequestFactoryInterface;
use function WP_DEFENDER_VENDOR\Safe\json_decode;
use function WP_DEFENDER_VENDOR\Safe\sprintf;

class DistantSingleMetadata extends SingleMetadata
{
    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var array
     */
    private $additionalHeaders;

    /**
     * @var string
     */
    private $uri;

    /**
     * @var bool
     */
    private $isBase64Encoded;

    public function __construct(string $uri, bool $isBase64Encoded, ClientInterface $httpClient, RequestFactoryInterface $requestFactory, array $additionalHeaders = [])
    {
        parent::__construct($uri, $isBase64Encoded); //Useless
        $this->uri = $uri;
        $this->isBase64Encoded = $isBase64Encoded;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->additionalHeaders = $additionalHeaders;
    }

    public function getMetadataStatement(): MetadataStatement
    {
        $payload = $this->fetch();
        $json = $this->isBase64Encoded ? Base64Url::decode($payload) : $payload;
        $data = json_decode($json, true);

        return MetadataStatement::createFromArray($data);
    }

    private function fetch(): string
    {
        $request = $this->requestFactory->createRequest('GET', $this->uri);
        foreach ($this->additionalHeaders as $k => $v) {
            $request = $request->withHeader($k, $v);
        }
        $response = $this->httpClient->sendRequest($request);
        Assertion::eq(200, $response->getStatusCode(), sprintf('Unable to contact the server. Response code is %d', $response->getStatusCode()));
        $content = $response->getBody()->getContents();
        Assertion::notEmpty($content, 'Unable to contact the server. The response has no content');

        return $content;
    }
}
