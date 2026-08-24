<?php

declare(strict_types=1);

namespace WP_DEFENDER_VENDOR\Brick\Math\Exception;

/**
 * Base class for all math exceptions.
 *
 * This class is abstract to ensure that only fine-grained exceptions are thrown throughout the code.
 */
class MathException extends \RuntimeException
{
}
