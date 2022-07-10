<?php

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

require_once('bcrypthmackeys.php');

// For bcrypt, the current minimum cost is 9 (July 2022).
// This makes attackers get <10 kH/s/GPU.
// Specifically an RTX 3080 12GB should get around 5.3 kH/s.
// For rough cost benchmarks see https://gist.github.com/roycewilliams/d231a65288de688b1c0fa27a1822ce53
// For current minimums see https://tobtu.com/minimum-password-settings
//
// **DO NOT** increase cost to above 14. Cost is exponential and you will DoS yourself.
// Cost 12 is really high. Cost 13 is crazy high. Cost 14 is ludicrously high.
define('BCRYPT_HMAC_COST', ['cost' => 9], false);

// Change this if you like but needs to be at least one character and doesn't collide with your existing hashes.
define('BCRYPT_HMAC_PREFIX', '$key_id=', false);


/**
 * Hashes a password with bcrypt and the current HMAC key.
 *
 * @param string $password - The password to be hashed.
 * @retur string - The hash of the password.
 */
function bcryptHmac_hash($password)
{
	// HMAC: the password is the message and the output is in lowercase hex.
	$password = hash_hmac('sha256', $password, BCRYPT_HMAC_KEYS[BCRYPT_HMAC_KEYS_CURRENT_ID]);
	$hash = password_hash($password, PASSWORD_BCRYPT, BCRYPT_HMAC_COST);

	return BCRYPT_HMAC_PREFIX . BCRYPT_HMAC_KEYS_CURRENT_ID . $hash;
}

/**
 * Checks if the password with bcrypt and the current HMAC key.
 *
 * @param string $password - The password to be checked.
 * @param string $hash - The hash to check against.
 * @return bool - true if the password is correct, otherwise false.
 */
function bcryptHmac_verify($password, $hash)
{
	$check = false;

	if (substr($hash, 0, strlen(BCRYPT_HMAC_PREFIX)) === BCRYPT_HMAC_PREFIX)
	{
		$pos = strpos($hash, '$', strlen(BCRYPT_HMAC_PREFIX));
		if ($pos !== false)
		{
			$keyId = substr($hash, strlen(BCRYPT_HMAC_PREFIX), $pos - strlen(BCRYPT_HMAC_PREFIX));
			if (isset(BCRYPT_HMAC_KEYS[$keyId]))
			{
				$hash = substr($hash, strlen(BCRYPT_HMAC_PREFIX) + strlen($keyId));
				$check = password_verify(hash_hmac('sha256', $password, BCRYPT_HMAC_KEYS[$keyId]), $hash);
			}
			else
			{
				error_log('Key ID (base64_decode(' . base64_encode($keyId) . ')) not in BCRYPT_HMAC_KEYS');
			}
		}
		else
		{
			error_log('Invalid bcrypt-HMAC hash');
		}
	}
	else
	{
		// TODO: Replace this with your legacy password code.
		// Note this can verify any hash created with crypt() or password_hash().
		$check = password_verify($password, $hash);
	}

	return $check;
}

/**
 * Checks if the hash is old and needs to be rehashed.
 *
 * @param string $hash.
 * @return bool - true if the hash is old, otherwise false.
 */
function bcryptHmac_needsRehash($hash)
{
	$rehash = true;
	$currentPrefix = BCRYPT_HMAC_PREFIX . BCRYPT_HMAC_KEYS_CURRENT_ID;
	if (substr($hash, 0, strlen($currentPrefix) + 1) === $currentPrefix . '$')
	{
		$rehash = password_needs_rehash(substr($hash, strlen($currentPrefix)), PASSWORD_BCRYPT, BCRYPT_HMAC_COST);
	}
	return $rehash;
}
