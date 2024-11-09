# PyPass
Secure Password Generator


# Key Points of the Encryption:
*AES Encryption: Fernet uses AES in CBC mode with a 128-bit key for encryption.
*HMAC for Authentication: Fernet includes HMAC (Hash-based Message Authentication Code) to ensure the integrity and authenticity of the data.
*Base64 Encoding: Encrypted data is Base64-encoded to make it safe for storage or transmission in textual formats.

# How Vault Encryption Works:
*When you create the vault, data is encrypted with the Fernet key derived from the user's master password using PBKDF2 (Password-Based Key Derivation Function 2) with SHA256 for hashing and a fixed salt.
*The encrypted vault is stored as a file (password_vault.enc).
*When accessing the vault, the same key derived from the master password is used to decrypt the data.
