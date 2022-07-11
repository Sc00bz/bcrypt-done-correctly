<?php namespace Sc00bz\bcrypt_done_correctly;

/*
	Copyright (c) 2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

/**
 * The base exception class for BcryptHmac.
 */
class BcryptHmacException extends \Exception
{
	public function __construct($msg, $code)
	{
		parent::__construct($msg, $code);
	}
}

class BcryptHmacCurrentKeyAlreadySetException extends BcryptHmacException
{
	public function __construct() { parent::__construct('Current key already set', 1); }
}

class BcryptHmacAlgoNotSupportedException extends BcryptHmacException
{
	public function __construct() { parent::__construct('HMAC algorithm not supported', 2); }
}

class BcryptHmacKeyIdAlreadyExistsException extends BcryptHmacException
{
	public function __construct() { parent::__construct('Key ID already exists', 3); }
}

class BcryptHmacKeyInvalidIdException extends BcryptHmacException
{
	public function __construct() { parent::__construct('Invalid key ID', 4); }
}

class BcryptHmacKeyIdIsTheKeyException extends BcryptHmacException
{
	public function __construct() { parent::__construct('Key ID is the same as the key', 5); }
}

class BcryptHmacKeyIdDoesNotExistException extends BcryptHmacException
{
	public function __construct() { parent::__construct('Key ID does not exist', 6); }
}

class BcryptHmacInvalidHashException extends BcryptHmacException
{
	public function __construct() { parent::__construct('Invalid BcryptHmac hash', 7); }
}

class BcryptHmacCurrentKeyIdDoesNotExistException extends BcryptHmacException
{
	public function __construct() { parent::__construct('Current key ID does not exist', 8); }
}

/**
 * Static class for dealing with "bcrypt HMAC" hashes.
 *
 * Algorithm is bcrypt(lowercaseHex(hmac(message = password, key)), cost).
 */
class BcryptHmac
{
	/**
	 * List of valid HMAC algorithms.
	 *
	 * @access private
	 * @var array
	 */
	private const ALGOS =
		[
			'sha224' => true,
			'sha256' => true,
			'sha384' => true,
			'sha512/224' => true,
			'sha512/256' => true,
			'sha512' => true,
			'sha3-224' => true,
			'sha3-256' => true,
			'sha3-384' => true,
			'sha3-512' => true
		];

	/**
	 * A list of HMAC keys.
	 *
	 * @access private
	 * @var array
	 */
	private static $keys = [];

	/**
	 * The current key's ID.
	 *
	 * @access private
	 * @var string
	 */
	private static $currentKeyId;

	/**
	 * For bcrypt, the current minimum cost is 9 (July 2022).
	 * This makes attackers get <10 kH/s/GPU.
	 * Specifically an RTX 3080 12GB should get around 5.3 kH/s.
	 * For rough cost benchmarks see https://gist.github.com/roycewilliams/d231a65288de688b1c0fa27a1822ce53
	 * For current minimums see https://tobtu.com/minimum-password-settings
	 *
	 * @access private
	 * @var int
	 */
	private const COST_MIN = 9;

	/**
	 * **DO NOT** increase cost to above 14. Cost is exponential and you will DoS yourself.
	 * Cost 12 is really high. Cost 13 is crazy high. Cost 14 is ludicrously high.
	 *
	 * @access private
	 * @var int
	 */
	private const COST_MAX = 16;

	/**
	 * Change this if you like but needs to be at least one 
	 * character and doesn't collide with your existing hashes.
	 *
	 * @access private
	 * @var string
	 */
	private const PREFIX = '$key_id=';

	/**
	 * Can't create this object.
	 *
	 * @access private
	 */
	private function __construct() {}

	/**
	 * Can't clone this object.
	 *
	 * @access private
	 */
	private function __clone() {}

	/**
	 * Can't unserialize this object.
	 *
	 * @access private
	 */
	private function __wakeup() {}

	/**
	 * Adds an HMAC key to the list of available HMAC keys.
	 *
	 * You could have the key ID be a truncated hash of the key (like 32-64 bits
	 * which is 8-16 hex digits). This will let you see if a key ID matches the
	 * key. For nicer change logs put one key per line and end with a comma.
	 *
	 * Generate a key like this bin2hex(random_bytes(16)) once use it's output.
	 *
	 * @access public
	 * @param bool $isCurrentKey - Whether this key is used for new hashes.
	 * @param string $keyId - The ID of the key. This is put into the hash to identify which key was used
	 * @param string $key - The HMAC key.
	 * @param string $keyAlgo - .
	 * @throws BcryptHmacCurrentKeyAlreadySetException
	 * @throws BcryptHmacAlgoNotSupportedException
	 * @throws BcryptHmacKeyIdAlreadyExistsException
	 * @throws BcryptHmacKeyInvalidIdException
	 * @throws BcryptHmacKeyIdIsTheKeyException
	 */
	static function addKey($isCurrentKey, $keyId, $key, $keyAlgo = 'sha256')
	{
		if (!hash_equals($keyId, $key))
		{
			if (strpos($keyId, '$') === false)
			{
				if (!isset(self::$keys[$keyId]))
				{
					$keyAlgo = strtolower($keyAlgo);
					if (isset(self::ALGOS[$keyAlgo]))
					{
						self::$keys[$keyId] = [$key, $keyAlgo];
						if ($isCurrentKey)
						{
							if (!isset(self::$currentKeyId))
							{
								self::$currentKeyId = $keyId;
							}
							else
							{
								throw new BcryptHmacCurrentKeyAlreadySetException();
							}
						}
					}
					else
					{
						throw new BcryptHmacAlgoNotSupportedException();
					}
				}
				else
				{
					throw new BcryptHmacKeyIdAlreadyExistsException();
				}
			}
			else
			{
				throw new BcryptHmacKeyInvalidIdException();
			}
		}
		else
		{
			throw new BcryptHmacKeyIdIsTheKeyException();
		}
	}

	/**
	 * Hashes a password with bcrypt and the current HMAC key.
	 *
	 * @access public
	 * @param string $password - The password to be hashed.
	 * @param int $cost - The bcrypt cost.
	 * @return string - The hash of the password.
	 * @throws BcryptHmacCurrentKeyIdDoesNotExistException
	 */
	static function hash($password, $cost = self::COST_MIN)
	{
		if ($cost < self::COST_MIN)
		{
			$cost = self::COST_MIN;
		}
		else if ($cost > self::COST_MAX)
		{
			$cost = self::COST_MAX;
		}

		if (!isset(self::$keys[self::$currentKeyId]))
		{
			throw new BcryptHmacCurrentKeyIdDoesNotExistException();
		}
		$key = self::$keys[self::$currentKeyId];
		$password = hash_hmac($key[1], $password, $key[0]);
		$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => $cost]);

		return self::PREFIX . self::$currentKeyId . $hash;
	}

	/**
	 * Checks if the password with bcrypt and the current HMAC key.
	 *
	 * @access public
	 * @param string $password - The password to be checked.
	 * @param string $hash - The hash to check against.
	 * @throws BcryptHmacKeyIdDoesNotExistException
	 * @throws BcryptHmacInvalidHashException
	 * @return bool - true if the password is correct, otherwise false.
	 */
	static function verify($password, $hash)
	{
		$check = false;

		if (substr($hash, 0, strlen(self::PREFIX)) === self::PREFIX)
		{
			$pos = strpos($hash, '$', strlen(self::PREFIX));
			if ($pos !== false)
			{
				$keyId = substr($hash, strlen(self::PREFIX), $pos - strlen(self::PREFIX));
				if (isset(self::$keys[$keyId]))
				{
					$hash = substr($hash, strlen(self::PREFIX) + strlen($keyId));
					$key = self::$keys[$keyId];
					$password = hash_hmac($key[1], $password, $key[0]);
					$check = password_verify($password, $hash);
				}
				else
				{
					throw new BcryptHmacKeyIdDoesNotExistException();
				}
			}
			else
			{
				throw new BcryptHmacInvalidHashException();
			}
		}
		else
		{
			throw new BcryptHmacInvalidHashException();
		}

		return $check;
	}

	/**
	 * Checks if the hash is old and needs to be rehashed.
	 *
	 * @access public
	 * @param string $hash - The hash to check.
	 * @param int $cost - Current bcrypt cost.
	 * @return bool - true if the hash is old, otherwise false.
	 */
	static function needsRehash($hash, $cost = self::COST_MIN)
	{
		$rehash = true;
		$currentPrefix = self::PREFIX . self::$currentKeyId;
		if (substr($hash, 0, strlen($currentPrefix) + 1) === $currentPrefix . '$')
		{
			if ($cost < self::COST_MIN)
			{
				$cost = self::COST_MIN;
			}
			else if ($cost > self::COST_MAX)
			{
				$cost = self::COST_MAX;
			}
			$rehash = password_needs_rehash(substr($hash, strlen($currentPrefix)), PASSWORD_BCRYPT, ['cost' => $cost]);
		}
		return $rehash;
	}

	/**
	 * Checks if the hash is compatible with BcryptHmac and key ID is available.
	 *
	 * @access public
	 * @param string $hash.
	 * @return bool - true if the hash is compatible, otherwise false.
	 */
	static function isValidHash($hash)
	{
		$compatible = false;
		if (substr($hash, 0, strlen(self::PREFIX)) === self::PREFIX)
		{
			$pos = strpos($hash, '$', strlen(self::PREFIX));
			if ($pos !== false)
			{
				$keyId = substr($hash, strlen(self::PREFIX), $pos - strlen(self::PREFIX));
				$compatible = isset(self::$keys[$keyId]);
			}
		}
		return $compatible;
	}
}

// Auto generate a key if there are no keys in bcrypthmackeys.php
$bcrypthmackeys_php = file_get_contents('bcrypthmackeys.php');
if ($bcrypthmackeys_php !== false)
{
	if (strpos($bcrypthmackeys_php, 'addKey') === false)
	{
		$key = 'BcryptHmac::addKey(true, \'0\', \'' . bin2hex(random_bytes(16)) . '\');';
		$bytesWritten = file_put_contents('bcrypthmackeys.php', $key, FILE_APPEND);
		if ($bytesWritten !== false && $bytesWritten !== strlen($key) && $bytesWritten !== 0)
		{
			error_log('******** OH NO ********');
			throw new BcryptHmacException('Oh no I tried to write a new key to bcrypthmackeys.php and it only wrote part of the data.', -1);
		}
	}
}

require_once('bcrypthmackeys.php');
