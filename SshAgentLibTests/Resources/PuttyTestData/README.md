PuTTY test data
===============

Public key files
----------------

Public key files are not included here since PuTTY uses the same format as
OpenSSH.


Private key files
-----------------

The file names for PuTTY private keys use the following format:

    <key type>[-<curve>]-<ppk version>-<encryption>[-<key derivation>].ppk

where `<key-type>` is one of:
- `rsa`
- `dsa`
- `ecdsa`
- `eddsa`
- `ssh1`

and if `<key-type>` is `ecdsa`, then `<curve>` is one of:
- `nistp256`
- `nistp384`
- `nistp521`

or if `<key-type>` is `eddsa`, then `<curve>` is one of:
- `ed25519`
- `ed448`

and `<ppk version>` is the file format version:
- `v1`
- `v2`
- `v3`

and `<encryption>` is the encryption algorithm:
- `none`
- `aes256cbc`

and `<key derivation>` is the key derivation algorithm (v3 only):
- `none`
- `argon2id`
- `argon2i`
- `argon2d`

Parameters
----------

All key files of the same key type must be the same key and therefore have the
same parameters. Individual parameters are stored in individual files as an
ASCII string representing a base 10 number.

    <key type>[-<curve>].param.<param name>

Where `<key type>[-<curve>]` matches the file name above and `<param name>` is the lower-
case name of the parameter.

Passphrase
----------

The same passphrase is used for all private key files with encryption. It is
stored in the file named `pass`.
