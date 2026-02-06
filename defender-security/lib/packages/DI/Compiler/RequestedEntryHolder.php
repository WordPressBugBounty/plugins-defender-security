<?php

declare(strict_types=1);

namespace WPMU_DEV\Defender\Vendor\DI\Compiler;

use WPMU_DEV\Defender\Vendor\DI\Factory\RequestedEntry;

/**
 * @author Matthieu Napoli <matthieu@mnapoli.fr>
 */
class RequestedEntryHolder implements RequestedEntry
{
    public function __construct(
        private string $name,
    ) {
    }

    public function getName() : string
    {
        return $this->name;
    }
}
