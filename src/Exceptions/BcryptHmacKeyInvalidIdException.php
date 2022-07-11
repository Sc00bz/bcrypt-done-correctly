<?php

namespace Sc00bz\BcryptDoneCorrectly\Exceptions;

class BcryptHmacKeyInvalidIdException extends BcryptHmacException
{
	public function __construct()
    {
        parent::__construct('Invalid key ID', 3);
    }
}
