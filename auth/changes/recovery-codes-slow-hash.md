### Recovery codes are stored as a slow hash

A recovery code is now stored as argon2id of the code, salted by the account,
instead of its plain SHA-256: a read of the `UserRecoveryCode` table (a backup, a
replica) no longer lets the unused codes be searched offline in hours. Sets made
before keep working, each code once, with no data migration and no schema change; a
person who generates a new set (`GenerateRecoveryCodes`) moves to the slow hash. A
recovery-shaped code that matches nothing now costs two lookups (the slow hash,
then the old digest).
