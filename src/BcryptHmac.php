<?php

namespace Sc00bz\BcryptDoneCorrectly;

use Sc00bz\BcryptDoneCorrectly\Exceptions;

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
 * Class for dealing with "bcrypt HMAC" hashes.
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
	private const ALGOS = [
        'sha224' => true,
        'sha256' => true,
        'sha384' => true,
        'sha512/224' => true,
        'sha512/256' => true,
        'sha512' => true,
        'sha3-224' => true,
        'sha3-256' => true,
        'sha3-384' => true,
        'sha3-512' => true,
	];

    private const DEFAULT_ALGO = 'sha256';

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
	 * @access private
	 * @var string
	 */
	private const DEFAULT_PREFIX = '$key_id=';

    /**
     * Needs to be at least one character and
     * doesn't collide with your existing hashes.
     *
     * @access private
     * @var string
     */
    private $prefix;

    /**
     * The current key's ID.
     *
     * @access private
     * @var string
     */
    private $currentKeyId;

    /**
     * The configured HMAC keys, as a map to support rotation.
     *
     * To do a key rotation:
     *   - Generate a key with something like: bin2hex(random_bytes(16))
     *   - Determine the key ID; you could have the key ID be a truncated
     *     hash of the key (like 32-64 bits which is 8-16 hex digits);
     *     this will let you see if a key ID matches the key.
     *   - Add the new key and ID to the constructor $keys.
     *   - Update $currentKeyId to the new key ID.
     *   - When all old hashes have been updated with the new key,
     *     you can remove the old key from the array.
     *
     * DO NOT include a '$' character in the key ID.
     * DO NOT use a key ID that is the same as the key itself.
     * Keep your keys untracked by git, in some config file.
     * Use different keys in production vs development.
     *
     * @access private
     * @var array<string, array{0: string, 1: string}>
     */
    private $keys;

    /**
     * @param string $currentKeyId The current key's ID.
     * @param string $prefix A prefix for identifying HMAC'd password hashes.
     */
    public function __construct(string $currentKeyId, string $prefix = self::DEFAULT_PREFIX)
    {
        $this->currentKeyId = $currentKeyId;
        $this->prefix = $prefix;
    }

    /**
     * Adds an HMAC key to the list of available HMAC keys.
     *
     * You could have the key ID be a truncated hash of the key (like 32-64 bits
	 * which is 8-16 hex digits). This will let you see if a key ID matches the
	 * key. For nicer change logs put one key per line and end with a comma.
	 *
	 * Generate a key like this bin2hex(random_bytes(16)) once use it's output.
     *
     * @param string $id The ID of the key. This is put into the hash to identify which key was used.
	 * @param string $key The HMAC key.
	 * @param string $algo The HMAC algorithm.
     * @throws BcryptHmacException
     */
    public function addKey(string $id, string $key, string $algo = self::DEFAULT_ALGO)
    {
        $this->validateKey($id, $key, $algo);
        $this->keys[$id] = [$key, \strtolower($algo)];
    }

    /**
     * Hashes a password with bcrypt and the current HMAC key.
     *
     * @param string $password The password to be hashed.
     * @param int $cost The bcrypt cost.
     * @return string
     * @throws BcryptHmacException
     */
    public function hash(string $password, int $cost = self::COST_MIN): string
    {
		if ($cost < self::COST_MIN) {
			$cost = self::COST_MIN;
		} else if ($cost > self::COST_MAX) {
			$cost = self::COST_MAX;
		}

        if (!isset($this->keys[$this->currentKeyId])) {
            throw new Exceptions\BcryptHmacCurrentKeyIdDoesNotExistException();
        }

        $key = $this->keys[$this->currentKeyId];

        $password = \hash_hmac($key[1], $password, $key[0]);
        $hash = \password_hash($password, \PASSWORD_BCRYPT, ['cost' => $cost]);

        return "{$this->prefix}{$this->currentKeyId}{$hash}";
    }

    /**
     * Verify that the password matches the hash with bcrypt and the current HMAC key.
     *
     * @param string $password The password to be checked.
     * @param string $hash The hash to check against.
     * @return bool
     * @throws BcryptHmacException
     */
    public function verify(string $password, string $hash): bool
    {
        if (!\str_starts_with($hash, $this->prefix)) {
            throw new Exceptions\BcryptHmacInvalidHashException();
        }

        $prefixLen = \strlen($this->prefix);

        // Find the first '$' after the prefix
        $pos = \strpos($hash, '$', $prefixLen);
        if ($pos === false) {
            throw new Exceptions\BcryptHmacInvalidHashException();
        }

        // Grab the key ID from the hash, after the prefix and before the next '$'
        $keyId = \substr($hash, $prefixLen, $pos - $prefixLen);
        if (!isset($this->keys[$keyId])) {
            throw new Exceptions\BcryptHmacKeyIdDoesNotExistException();
        }

        $hash = \substr($hash, $prefixLen + \strlen($keyId));
        $key = $this->keys[$keyId];
        $password = \hash_hmac($key[1], $password, $key[0]);

        return \password_verify($password, $hash);
    }

    /**
     * Checks if the hash is old and needs to be rehashed.
     *
     * @param string $hash The previously hashed password.
     * @param int $cost The bcrypt cost.
     * @return bool
     */
    public function needsRehash(string $hash, int $cost = self::COST_MIN): bool
    {
        if (!\str_starts_with($hash, "{$this->prefix}{$this->currentKeyId}$")) {
            return true;
        }

        if ($cost < self::COST_MIN) {
			$cost = self::COST_MIN;
		} else if ($cost > self::COST_MAX) {
			$cost = self::COST_MAX;
		}

        $wrapped = \substr($hash, \strlen($this->prefix));

        return \password_needs_rehash($wrapped, \PASSWORD_BCRYPT, ['cost' => $cost]);
    }

    /**
     * Validate that a key to be added (ID, value, algo) is valid.
     *
     * @throws BcryptHmacException
     */
    private function validateKey(string $id, string $key, string $algo = self::DEFAULT_ALGO): void
    {
        if (\hash_equals($id, $key)) {
            throw new Exceptions\BcryptHmacKeyIdIsTheKeyException();
        }

        if (\str_contains($key, "$")) {
            throw new Exceptions\BcryptHmacKeyInvalidIdException();
        }

        if (isset($this->keys[$id])) {
            throw new Exceptions\BcryptHmacKeyIdAlreadyExistsException();
        }

        $algo = \strtolower($algo);
        if (!isset(self::ALGOS[$algo])) {
            throw new Exceptions\BcryptHmacAlgoNotSupportedException();
        }
    }
}
