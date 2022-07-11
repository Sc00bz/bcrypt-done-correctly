<?php

namespace Sc00bz\BcryptDoneCorrectly\Exceptions;

class BcryptHmacKeyIdAlreadyExistsException extends BcryptHmacException
{
	public function __construct()
    {
        parent::__construct('Key ID already exists', 2);
    }
}
