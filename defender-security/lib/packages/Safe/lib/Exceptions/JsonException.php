<?php


namespace WP_DEFENDER_VENDOR\Safe\Exceptions;

class JsonException extends \Exception implements SafeExceptionInterface
{
    public static function createFromPhpError(): self
    {
        return new self(\json_last_error_msg(), \json_last_error());
    }
}
