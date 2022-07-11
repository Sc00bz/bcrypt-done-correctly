<?php

namespace Sc00bz\BcryptDoneCorrectly\Exceptions;

class BcryptHmacCurrentKeyIdDoesNotExistException extends BcryptHmacException
{
	public function __construct()
    {
        parent::__construct('Current key ID does not exist', 7);
    }
}
