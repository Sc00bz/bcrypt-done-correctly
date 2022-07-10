<?php

// *************
// ** WARNING **
// *************
// You should have production and developer versions of this file.
// Basically your real keys should not be published on GitHub or where ever.


// To do a key rotation add a new key and ID.
// Then update BCRYPT_HMAC_KEYS_CURRENT_ID to the new key ID.
// When all old hashes have been updated with the new key, you can remove the old key from the array.
define('BCRYPT_HMAC_KEYS',
	[
		// **DO NOT** include a $ in your key ID.
		// Key ID should **NOT** be the same as the key.
		// You could have the key ID be a truncated hash of the key (like 32-64 bits which is 8-16 hex digits).
		// This will let you see if a key ID matches the key.
		// For nicer change logs put one key per line and end with a comma.
		'null_key' => '', // TODO: Generate a key like: bin2hex(random_bytes(16))
	], false);

// TODO: Set to your generated key's ID
define('BCRYPT_HMAC_KEYS_CURRENT_ID', 'null_key_error', false);

// Example:
// define('BCRYPT_HMAC_KEYS', ['0' => 'Example key do not use this'], false);
// define('BCRYPT_HMAC_KEYS_CURRENT_ID', '0', false);
