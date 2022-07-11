<?php

use Sc00bz\BcryptDoneCorrectly\BcryptHmac;

require_once __DIR__ . '/../vendor/autoload.php';


$password = $oldPassword = 'password';
$newPassword = $newPassword2 = 'password1';

// ***************************
// *** Setup with HMAC key ***
// ***************************
$bcryptHmac = new BcryptHmac('1');
$bcryptHmac->addKey('1', bin2hex(random_bytes(16))); // TODO: Store the key somewhere safe


// ****************
// *** New user ***
// ****************
echo "****************<br />\n*** New user ***<br />\n****************<br />\n";
$hash = $bcryptHmac->hash($password);
echo "TODO: Insert $hash into DB<br />\n"; // TODO: Insert $hash into DB


// *************
// *** Login ***
// *************
echo "<br />\n*************<br />\n*** Login ***<br />\n*************<br />\n";
echo "TODO: Get $hash from DB<br />\n"; // TODO: Get $hash from DB
if ($bcryptHmac->verify($password, $hash)) {
	if ($bcryptHmac->needsRehash($hash)) {
		$hash = $bcryptHmac->hash($password);
		echo "TODO: Update $hash in DB<br />\n"; // TODO: Update $hash in DB
	}
	echo "TODO: User is logged in<br />\n"; // TODO: User is logged in
} else {
	echo "TODO: Error wrong password<br />\n"; // TODO: Error wrong password
}


// ***********************
// *** Change password ***
// ***********************
echo "<br />\n***********************<br />\n*** Change password ***<br />\n***********************<br />\n";
if ($newPassword === $newPassword2) {
	echo "TODO: Get $hash from DB<br />\n"; // TODO: Get $hash from DB
	$check = $bcryptHmac->verify($oldPassword, $hash);
	if ($check) {
		$hash = $bcryptHmac->hash($newPassword);
		echo "TODO: Update $hash in DB<br />\n"; // TODO: Update $hash in DB
		echo "TODO: Return success message to user<br />\n"; // TODO: Return success message to user
	} else {
		echo "TODO: Error wrong password<br />\n"; // TODO: Error wrong password
	}
} else {
	echo "TODO: Error new passwords don't match<br />\n"; // TODO: Error new passwords don't match
}
