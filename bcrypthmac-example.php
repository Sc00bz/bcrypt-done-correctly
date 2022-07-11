<?php

require_once('bcrypthmac.php');

$password = $oldPassword = 'password';
$newPassword = $newPassword2 = 'password1';


// ****************
// *** New user ***
// ****************
echo "****************<br />\n*** New user ***<br />\n****************<br />\n";
$hash = Sc00bz\bcrypt_done_correctly\BcryptHmac::hash($password);
echo "TODO: Insert $hash into DB<br />\n"; // TODO: Insert $hash into DB


// *************
// *** Login ***
// *************
echo "<br />\n*************<br />\n*** Login ***<br />\n*************<br />\n";
echo "TODO: Get $hash from DB<br />\n"; // TODO: Get $hash from DB
if (Sc00bz\bcrypt_done_correctly\BcryptHmac::verify($password, $hash))
{
	if (Sc00bz\bcrypt_done_correctly\BcryptHmac::needsRehash($hash))
	{
		$hash = Sc00bz\bcrypt_done_correctly\BcryptHmac::hash($password);
		echo "TODO: Update $hash in DB<br />\n"; // TODO: Update $hash in DB
	}
	echo "TODO: User is logged in<br />\n"; // TODO: User is logged in
}
else
{
	echo "TODO: Error wrong password<br />\n"; // TODO: Error wrong password
}


// ***********************
// *** Change password ***
// ***********************
echo "<br />\n***********************<br />\n*** Change password ***<br />\n***********************<br />\n";
if ($newPassword === $newPassword2)
{
	echo "TODO: Get $hash from DB<br />\n"; // TODO: Get $hash from DB
	$check = Sc00bz\bcrypt_done_correctly\BcryptHmac::verify($oldPassword, $hash);
	if ($check)
	{
		$hash = Sc00bz\bcrypt_done_correctly\BcryptHmac::hash($newPassword);
		echo "TODO: Update $hash in DB<br />\n"; // TODO: Update $hash in DB
		echo "TODO: Return success message to user<br />\n"; // TODO: Return success message to user
	}
	else
	{
		echo "TODO: Error wrong password<br />\n"; // TODO: Error wrong password
	}
}
else
{
	echo "TODO: Error new passwords don't match<br />\n"; // TODO: Error new passwords don't match
}
