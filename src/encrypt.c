#include "encrypt.h"
#include "utils.h"

int encrypt_file(const char *input_filename, const char *output_filename, const char *password) {
    // init necessary vars
    int res = 0;
    unsigned char key[AES_KEYLEN / 8] = {'\0'}; // 33 bytes in size (inc. NULL terminator)

    // basic IO vars
    FILE *input_file = fopen(input_filename, "rb"); // open the input file for reading
    if (!input_file) {
        fprintf(stderr, "ERROR: failed to open files for encryption\n");
        res = FILE_OPEN_ERR;
        goto out_basic;
    }

    // checking if attempting to write over pre-existing file
    FILE *output_file = fopen(output_filename, "wb"); // open the output file for writing
    if (!output_file) {
        fprintf(stderr, "ERROR: failed to open files for encryption\n");
        res = FILE_OPEN_ERR;
        goto out_free_io_in;
    }

    // create the key using the password and fixed salt + IV
    derive_key(password, key); 

    // create an AES encryption context
    const unsigned char iv_16[] = { 0x6B, 0x1F, 0x2A, 0x3D, 0x44, 0x5B, 0x6C, 0x77, 0x89, 0x90, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x00 };
    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    int ctx_set_res = EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, key, (unsigned char*)iv_16);
    if (ctx_set_res == OPENSSL_FAIL) {
        fprintf(stderr, "ERROR: failed to init the aes context\n");
        res = SSL_ERR;
        goto out_free_io_all;
    }

    // init vars for O(n) encryption
    int reg_len = 0;
    int encrypted_len = 0;
    unsigned char reg_buf[1024];             // buf to read plaintext from the input file
    unsigned char encrypted_buf[1024 + AES_BLOCK_SIZE]; // buf to store encrypted data
    int enc_res = 0;
    size_t bytes_written = 0;

    // encrypt input file data, block by block
    while ((reg_len = fread(reg_buf, 1, sizeof(reg_buf), input_file)) > 0) {
        // encrypt the current block of plaintext
        enc_res = EVP_EncryptUpdate(aes_ctx, encrypted_buf, &encrypted_len, reg_buf, reg_len); 
        if (enc_res == OPENSSL_FAIL) { // checking if failed encryption occurs
            fprintf(stderr, "ERROR: failed to encrypt some data\n");
            res = SSL_ERR;
            goto out_free_all;
        }

        // write the encrypted data to the output file
        bytes_written = fwrite(encrypted_buf, 1, encrypted_len, output_file); 
        if ((size_t)encrypted_len > 0 && bytes_written != (size_t)encrypted_len) { // read more than 0 bytes but didnt write any
            fprintf(stderr, "ERROR: read bytes into buffer but could not write these to an output file\n");
            res = FILE_WRITE_ERR;
            goto out_free_all;
        }
    }

    // finalise encryption process (any remaining data)
    enc_res = EVP_EncryptFinal_ex(aes_ctx, encrypted_buf, &encrypted_len); 
    if (enc_res == OPENSSL_FAIL) {
        fprintf(stderr, "ERROR: failed to encrypt data\n");
        res = SSL_ERR;
        goto out_free_all;
    }

    bytes_written = fwrite(encrypted_buf, 1, encrypted_len, output_file); // write the final block of encrypted data to the output file
    if ((size_t)encrypted_len > 0 && bytes_written != (size_t)encrypted_len) {
        fprintf(stderr, "ERROR: failed to write bytes to output file\n");
        res = FILE_WRITE_ERR;
        goto out_free_all;
    }

    // freeing memory to avoid memory leaks
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