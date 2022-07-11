# bcrypt HMAC
If it can, using bcrypthmac.php for the first time will create a new random key in bcrypthmackeys.php.

# Algorithm
```
bcrypt(password:hmac_sha256_lowercase_hex(key:key, message:password))
```

# Example hashes
Password is "password":
```
$key_id=0$2y$09$YY8m5PTmcBhiGAVdYdN4LOALYYsPfa4GJjvh5Y4MNiEy22Hz82N52
$key_id=1$2y$09$358MWw87Ltee7fuSCzjVJ.9CUGtFPn1gmtPLLIsMxjXPdHFmrCWKu
$key_id=2$2y$09$U/7TFoehSSokHXZAZR6Dne6x75k.CaEk3NWRUhecWqMhdf.UcXU5e
```

```
$key_id=0$ uses HMAC key "89b16b8accc4e45eeede2a7e388a52b1"
$key_id=1$ uses HMAC key "b0c126234b55c6e431d35accc70f82f2"
$key_id=2$ uses HMAC key unhex("4f2f74a4d39be5a8b599e97ebdb0951c")
```
