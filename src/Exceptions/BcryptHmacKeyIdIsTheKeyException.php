<?php

namespace Sc00bz\BcryptDoneCorrectly\Exceptions;

class BcryptHmacKeyIdIsTheKeyException extends BcryptHmacException
{
	public function __construct()
    {
        parent::__construct('Key ID is the same as the key', 4);
    }
}
