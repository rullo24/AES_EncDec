# Overview
cr_aes_encdec is a CLI tool written in C that provides AES-based encryption and decryption of files. This tool ensures the confidentiality of files by allowing you to encrypt them with a password and decrypt them when needed. It supports safe operations by appending file extensions to avoid accidental overwrites and includes an optional feature to delete the original file after encryption or decryption.

## Compilation - Requirements 
OpenSSL is the only prerequisite library required for building this program. Install the necessary OpenSSL packages using the following command:
```bash
sudo apt install libssl-dev
```
## Compilation - Building
```bash
make
```
## Compilation - Cleanup
```bash
make clean
```

## Usage
```bash
./cr_aes_encdec -<flag> <flag_value> 
```
### Available Flags
| Flag       | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `-h`       | Displays the help menu.                                                    |
| `-e`       | Encrypt a file. Requires a file name and password.                         |
| `-d`       | Decrypt a file. Requires a file name and password.                         |
| `-p`       | Specifies the password for encryption or decryption.                       |
| `--recursive` | Recursively encrypts or decrypts all valid files within a specified folder (does not go into folders) |
| `--remove` | Deletes the original file after encryption or decryption (requires confirmation). |

### Encrypting Files
```bash
./cr_aes_encdec -e ./filename.txt -p mypassword
```
### Decrypting Files
```bash
./cr_aes_encdec -d ./filename.txt.crenc -p mypassword
```

## File Naming Conventions
To avoid accidentally overwriting existing data, both encrypted and decrypted files are formed as copies.
- Encrypted Files: Append .crenc to the original file name.
- Decrypted Files: Replace .crenc with .crdec in the file name.

## Safety Notes
- Always ensure to remember the password used for encryption; without it, decryption is impossible.
- Use the --remove flag with caution to avoid accidental data loss.