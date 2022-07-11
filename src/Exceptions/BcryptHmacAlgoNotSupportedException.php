<?php

namespace Sc00bz\BcryptDoneCorrectly\Exceptions;

class BcryptHmacAlgoNotSupportedException extends BcryptHmacException
{
	public function __construct()
    {
        parent::__construct('HMAC algorithm not supported', 1);
    }
}
