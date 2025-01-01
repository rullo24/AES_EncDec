#include <limits.h>
#include "decrypt.h"
#include "utils.h"

int decrypt_file(const char *input_filename, const char *output_filename, const char *password) {
    // init necessary vars   
    int res = 0;
    unsigned char key[AES_KEYLEN / 8] = {'\0'}; // 33 bytes in size (inc. NULL terminator)

    // basic IO vars
    FILE *input_file = fopen(input_filename, "rb"); // Open the input file for reading (encrypted data)
    if (!input_file) {
        fprintf(stderr, "ERROR: failed to open input file for decryption\n");
        res = FILE_OPEN_ERR;
        goto out_basic;
    }
    FILE *output_file = fopen(output_filename, "wb"); // Open the output file for writing (decrypted data)
    if (!output_file) {
        fprintf(stderr, "ERROR: failed to open output file for decryption\n");
        res = FILE_OPEN_ERR;
        goto out_free_io_in;
    }

    // re-create the previously used key using the password and fixed salt + IV
    derive_key(password, key);

    // create an AES encryption context
    const unsigned char iv_16[] = { 0x6B, 0x1F, 0x2A, 0x3D, 0x44, 0x5B, 0x6C, 0x77, 0x89, 0x90, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x00 };
    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    int ctx_set_res = EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, key, (unsigned char*)iv_16);
    if (ctx_set_res == OPENSSL_FAIL) {
        fprintf(stderr, "ERROR: failed to init the AES context\n");
        res = SSL_ERR;
        goto out_free_io_all;
    }

    // init vars for O(n) encryption
    int reg_len = 0;
    int decrypted_len = 0;
    unsigned char reg_buf[1024]; // buf to read ciphertext from input file
    unsigned char decrypted_buf[1024 + AES_BLOCK_SIZE]; // buf to store decrypted data
    int dec_res = 0;
    size_t bytes_written = 0;

    // decrypt input file data, block by block
    while ((reg_len = fread(reg_buf, 1, sizeof(reg_buf), input_file)) > 0) {
        // decrypt the current block of plaintext
        dec_res = EVP_DecryptUpdate(aes_ctx, decrypted_buf, &decrypted_len, reg_buf, reg_len); // Decrypt the current block of ciphertext
        if (dec_res == OPENSSL_FAIL) {
            fprintf(stderr, "ERROR: failed to decrypt some data\n");
            res = SSL_ERR;
            goto out_free_all;
        }

        // write decrypted data to output file
        bytes_written = fwrite(decrypted_buf, 1, decrypted_len, output_file); // Write the decrypted data to the output file
        if ((size_t)decrypted_len > 0 && bytes_written != (size_t)decrypted_len) {
            fprintf(stderr, "ERROR: read bytes into buffer but could not write these to an output file\n");
            res = FILE_WRITE_ERR;
            goto out_free_all;
        }
    }

    // finalise encryption process (any remaining data)
    dec_res = EVP_DecryptFinal_ex(aes_ctx, decrypted_buf, &decrypted_len);
    if (dec_res == OPENSSL_FAIL) {
        fprintf(stderr, "ERROR: failed to decrypt data\n");
        rm_file(output_filename);
        res = SSL_ERR;
        goto out_free_all;
    }

    bytes_written = fwrite(decrypted_buf, 1, decrypted_len, output_file); // Write the final block of decrypted data to the output file
    if ((size_t)decrypted_len > 0 && bytes_written != (size_t)decrypted_len) {
        fprintf(stderr, "ERROR: failed to write bytes to output file\n");
        res = FILE_WRITE_ERR;
        goto out_free_all;
    }

    // memory cleanup section
out_free_all:
    EVP_CIPHER_CTX_free(aes_ctx); 
out_free_io_all:
    fclose(output_file);
    output_file = NULL;
out_free_io_in:
    fclose(input_file);
    input_file = NULL;
out_basic:
    return res;
}