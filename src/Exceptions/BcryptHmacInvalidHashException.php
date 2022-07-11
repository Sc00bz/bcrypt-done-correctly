<?php

namespace Sc00bz\BcryptDoneCorrectly\Exceptions;

class BcryptHmacInvalidHashException extends BcryptHmacException
{
	public function __construct()
    {
        parent::__construct('Invalid BcryptHmac hash', 6);
    }
}
