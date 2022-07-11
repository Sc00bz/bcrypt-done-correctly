<?php namespace Sc00bz\bcrypt_done_correctly;

// *************  You should have production and developer
// ** WARNING **  versions of this file. Basically your real keys
// *************  should not be published on GitHub or where ever.

// How to do a key rotation:
// * Add a new key, ID, and set that to the current key.
// * Optionally when all old hashes have been updated with the new key,
//     then you can remove the old key from the array.

