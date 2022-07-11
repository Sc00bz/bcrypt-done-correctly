<?php

namespace Sc00bz\BcryptDoneCorrectly\Exceptions;

class BcryptHmacKeyIdDoesNotExistException extends BcryptHmacException
{
	public function __construct()
    {
        parent::__construct('Key ID does not exist', 5);
    }
}
