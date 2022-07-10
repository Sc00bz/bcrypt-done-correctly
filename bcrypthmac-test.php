<?php

define('BCRYPT_HMAC_KEYS',
	[
		'0' => '89b16b8accc4e45eeede2a7e388a52b1',
		'1' => 'b0c126234b55c6e431d35accc70f82f2',
		'2' => "\x4f\x2f\x74\xa4\xd3\x9b\xe5\xa8\xb5\x99\xe9\x7e\xbd\xb0\x95\x1c",
	], false);
define('BCRYPT_HMAC_KEYS_CURRENT_ID', '2', false);

// For testing purposes, suppress errors for redefining constants.
@require_once('bcrypthmac.php');

$hashes =
	[
		'$key_id=0$2y$09$YY8m5PTmcBhiGAVdYdN4LOALYYsPfa4GJjvh5Y4MNiEy22Hz82N52',
		'$key_id=1$2y$09$358MWw87Ltee7fuSCzjVJ.9CUGtFPn1gmtPLLIsMxjXPdHFmrCWKu',
		'$key_id=2$2y$09$U/7TFoehSSokHXZAZR6Dne6x75k.CaEk3NWRUhecWqMhdf.UcXU5e',
	];

function testHashes($hashes, $password)
{
	foreach ($hashes as $hash)
	{
		echo $password . ':' . $hash . "<br />\n";
		if (bcryptHmac_verify($password, $hash))
		{
			echo 'correct password, ' . (bcryptHmac_needsRehash($hash) ? 'needs rehashing' : 'current');
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
