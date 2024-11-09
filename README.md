# PyPass - Secure Password Generator and Manager

PyPass is a secure and user-friendly password management tool that allows you to generate, store, and manage your passwords safely using an encrypted vault. The tool leverages AES encryption (via `cryptography.Fernet`) for robust security, ensuring that only authorized users can access stored passwords.

## Features

### 1. Create Vault
- Easily create a new encrypted vault file for storing your passwords.
- Set a master key, which is used to encrypt and decrypt the contents of your vault.
- Ensure the vault is securely protected, and only accessible by the correct master key.

### 2. Open Vault
- Unlock and view the contents of your vault by entering the correct master key.
- View saved passwords along with their associated nicknames for easy identification.
- Copy individual passwords to the clipboard using a convenient "Copy" button.

### 3. Generate Secure Passwords
- Generate strong, random passwords based on user-defined settings, such as:
  - Password length (minimum of 16 characters).
  - Inclusion/exclusion of uppercase letters, lowercase letters, numbers, and special characters.
  - Option to exclude similar characters (e.g., `1`, `l`, `0`, `O`) for improved readability.

### 4. Copy to Clipboard
- Copy generated passwords to the clipboard with a built-in timer that clears the clipboard after 30 seconds for enhanced security.

### 5. Save Passwords to Vault
- Save generated passwords to the encrypted vault with a user-defined "nickname" for easy organization and reference.

### 6. Password Strength Indicator
- Displays the strength of generated passwords as `Weak`, `Moderate`, or `Strong` based on criteria such as length and character diversity.

### 7. Show/Hide Password Toggle
- Easily toggle the visibility of generated passwords to view or conceal them as needed.


# Key Points of the Encryption:
*AES Encryption: Fernet uses AES in CBC mode with a 128-bit key for encryption.
*HMAC for Authentication: Fernet includes HMAC (Hash-based Message Authentication Code) to ensure the integrity and authenticity of the data.
*Base64 Encoding: Encrypted data is Base64-encoded to make it safe for storage or transmission in textual formats.

# How Vault Encryption Works:
*When you create the vault, data is encrypted with the Fernet key derived from the user's master password using PBKDF2 (Password-Based Key Derivation Function 2) with SHA256 for hashing and a fixed salt.
*The encrypted vault is stored as a file (password_vault.enc).
*When accessing the vault, the same key derived from the master password is used to decrypt the data.
