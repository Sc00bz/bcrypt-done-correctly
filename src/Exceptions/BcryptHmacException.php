<?php

namespace Sc00bz\BcryptDoneCorrectly\Exceptions;

use Exception;

/**
 * The base exception class for BcryptHmac.
 */
class BcryptHmacException extends Exception
{
	public function __construct($msg, $code)
	{
		parent::__construct($msg, $code);
	}
}
