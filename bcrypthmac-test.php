<?php

require('bcrypthmac.php');

Sc00bz\bcrypt_done_correctly\BcryptHmac::addKey(false, '1', '89b16b8accc4e45eeede2a7e388a52b1');
Sc00bz\bcrypt_done_correctly\BcryptHmac::addKey(false, '2', 'b0c126234b55c6e431d35accc70f82f2');
Sc00bz\bcrypt_done_correctly\BcryptHmac::addKey(false, '3', "\x4f\x2f\x74\xa4\xd3\x9b\xe5\xa8\xb5\x99\xe9\x7e\xbd\xb0\x95\x1c");

$hashes =
	[
		'$key_id=1$2y$09$YY8m5PTmcBhiGAVdYdN4LOALYYsPfa4GJjvh5Y4MNiEy22Hz82N52',
		'$key_id=2$2y$09$358MWw87Ltee7fuSCzjVJ.9CUGtFPn1gmtPLLIsMxjXPdHFmrCWKu',
		'$key_id=3$2y$09$U/7TFoehSSokHXZAZR6Dne6x75k.CaEk3NWRUhecWqMhdf.UcXU5e',
	];

function testHashes($hashes, $password)
{
	foreach ($hashes as $hash)
	{
		echo $password . ':' . $hash . "<br />\n";
		if (Sc00bz\bcrypt_done_correctly\BcryptHmac::verify($password, $hash))
		{
			echo 'correct password, ' . (Sc00bz\bcrypt_done_correctly\BcryptHmac::needsRehash($hash) ? 'needs rehashing' : 'current');
		}
		else
		{
			echo 'wrong password';
		}
		echo "<br />\n<br />\n";
	}
	echo "<br />\n";
}

testHashes($hashes, 'password');
testHashes($hashes, 'password1');
