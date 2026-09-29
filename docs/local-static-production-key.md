# Local production key provider

Set `APP_ENV=PROD` and `LOCAL_KMS_KEY_FILE` to an absolute path to a 32-byte
read-only file owned by the Superposition process. With this setting,
Superposition decrypts startup values locally and does not create an AWS KMS
client. Without it, the existing AWS KMS path is unchanged.

`scripts/local_kms.py init-key /absolute/path/to/key` creates a new key with
mode `0400`. Run it on the intended key host, keep an offline recovery copy,
and never add either copy to Git, SOPS source, a container image or logs.

Encrypt each startup secret using its exact environment variable name as
authenticated associated data:

```sh
scripts/local_kms.py encrypt /absolute/path/to/key DB_PASSWORD < private-input-file
```

The output has the form `local:v1:<base64(nonce || ciphertext || tag)>` and is
safe to place in the separately encrypted runtime values Secret. Protect and
remove the plaintext input file using the approved secret handling process.
Encrypt `DB_PASSWORD`, `SUPERPOSITION_TOKEN`, `OIDC_CLIENT_SECRET`, and
`MASTER_ENCRYPTION_KEY` where enabled; also encrypt prefixed database passwords
such as `CASBIN_DB_PASSWORD`. A ciphertext bound to one name will not decrypt
under another name. Existing AWS ciphertext is not compatible with this mode.

Mount the key file read-only into the Superposition Pod. A restart requires the
file to remain available; losing the file without a recovery copy makes the
encrypted values unreadable. Rotation needs a new key, re-encryption of every
startup value, rollout verification, and retention of the old key until the
new rollout and restore drill pass.
