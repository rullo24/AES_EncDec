// std C includes
#include <stdbool.h>
#include <string.h>
#include <dirent.h>

// user includes
#include "src/status.h"
#include "src/utils.h"
#include "src/encrypt.h"
#include "src/decrypt.h"
#include "src/linked.h"

void print_help() {
    printf("=== HELP MENU ===\n");
    printf("Usage: ./cr_aes_encdec -<flag> <flag_val> | i.e. ./cr_aes_encdec -d ./filename.txt -p password\n");
    printf("-h = Print this help menu\n");
    printf("-d = Decrypt File\n");
    printf("-e = Encrypt File\n");
    printf("-p = Provide password\n");
    printf("--recursive = Recursively encrypt/decrypt files within a directory (limited to the provided dir --> doesn't encrypt within folders)\n");
    printf("--remove = Delete the existing file\n");
    printf("=================\n");
}

int main(int argc, char **argv) {
    // init necessary variables
    int res = SUCCESS;
    struct user_flags flags = { .dec_file=NULL, .enc_file=NULL, .password=NULL, .help_flag=false, .remove_old_flag=false }; // memory allocated in argv
    struct path_node *p_path_LL_head = NULL;

    // no flags parsed
    if (argc == 1) { 
        print_help();
        res = SUCCESS;
        goto out_basic;
    }
 
    // gathers user data into flags struct --> also checks for filepath validity (returns err on invalidity)
    int get_flag_res = gather_user_flags(&flags, argc, argv);
    if (get_flag_res != SUCCESS) {
        res = get_flag_res;
        goto out_basic;
    }

    // checking if help flag provided
    if (flags.help_flag) {
        print_help();
        res = SUCCESS;
        goto out_basic;
    }

    // checking if user didn't provide relevant flags for decryption or encryption
    if (!flags.dec_file && !flags.enc_file) {
        fprintf(stderr, "ERROR: user did not provided relevant flags for encryption or decryption\n");
        res = INVALID_PARSE_ERR;
        goto out_basic;
    }

    // checking if user asked for decryption and encryption
    if (flags.dec_file && flags.enc_file) {
        fprintf(stderr, "ERROR: user asking for decryption and encryption simultaneously\n");
        res = ENC_AND_DEC_CONFLICT_ERR;
        goto out_basic;
    }

    // checking if password not provided for enc/dec
    if (!flags.password) {
        fprintf(stderr, "ERROR: no password provided for encryption/decryption process\n");
        res = INVALID_PARSE_ERR;
        goto out_basic;
    }


    // cryptography steps
    struct path_node *current_node = NULL;
    if (flags.enc_file) { // encryption process
        // adding files to LL (checks for directory/recursion internally)
        int add_files_ll_res = add_files_to_ll(&p_path_LL_head, flags.enc_file, flags.recursive_crypto_flag, 'e');
        if (add_files_ll_res != SUCCESS) {
            res = add_files_ll_res;
            goto out_free_ll;
        }
        
        // checking to avoid NULL deref (should never occur as prev checks should catch this)
        if (!p_path_LL_head) {
            fprintf(stderr, "ERROR: No files chosen for encryption | encryption string: (%s)\n", flags.enc_file);
            res = NULL_ERR;
            goto out_free_ll;
        }

        // iterating over all available paths (may only be one)
        current_node = p_path_LL_head; // var for traversing linked list
        while (current_node) {
            // if encrypting, check that not already encrypted (.crenc ext dne) --> err if exists
            if (substring_is_in_phrase(current_node->file_path, ".crenc")) { // already encrypted
                fprintf(stderr, "ERROR: user attempted to encrypt a pre-encrypted file\n");
                res = SHOULD_NOT_PERFORM_CRYPTO_ERR;
                goto out_free_ll;
            }

            // adding encryption extension to end of user-provided location for new file location
            size_t enc_file_path_len = strlen(current_node->file_path); 
            char new_enc_filepath[enc_file_path_len + strlen(".crenc") + 1]; // creating a buf to hold new filepath
            strncpy(new_enc_filepath, current_node->file_path, sizeof(new_enc_filepath)); // copying original string to new buf

            size_t remaining_space_enc_buf = sizeof(new_enc_filepath) - strlen(new_enc_filepath) - 1;
            strncat(new_enc_filepath, ".crenc", remaining_space_enc_buf); // copying encryption ext to end of filepath
            new_enc_filepath[sizeof(new_enc_filepath)-1] = '\0'; // ensuring that a NULL terminator exists

            // checking if new path is valid
            bool file_valid_flag = file_loc_valid(new_enc_filepath);
            if (!file_valid_flag) {
                fprintf(stderr, "ERROR: encryption path not valid (%s)", new_enc_filepath);
                res = INVALID_FILE_PATH_ERR;
                goto out_free_ll;
            }

            // encrypting file and saving to new location
            int enc_res = encrypt_file(current_node->file_path, new_enc_filepath, flags.password);
            if (enc_res != SUCCESS) {
                res = enc_res;
                goto out_free_ll;
            }
            printf("SUCCESS: Encrypted file stored at (%s)\n", new_enc_filepath);

            // moving to the next path in the linked list
            current_node = current_node->next; // could be NULL
        }

    } else if (flags.dec_file) { // decryption process
        // adding files to LL (checks for directory/recursion internally)
        int add_files_ll_res = add_files_to_ll(&p_path_LL_head, flags.dec_file, flags.recursive_crypto_flag, 'd');
        if (add_files_ll_res != SUCCESS) {
            res = add_files_ll_res;
            goto out_free_ll;
        }

        // checking to avoid NULL deref (should never occur as prev checks should catch this)
        if (!p_path_LL_head) {
            fprintf(stderr, "ERROR: No files chosen for decryption | decryption string: (%s)\n", flags.dec_file);
            res = NULL_ERR;
            goto out_free_ll;
        }

        // iterating over all available paths (may only be one)
        current_node = p_path_LL_head; // var for traversing linked list
        while (current_node) {

            // if decrypting, check that file is encrypted (.crenc ext exists)
            if (!substring_is_in_phrase(current_node->file_path, ".crenc")) {
                fprintf(stderr, "ERROR: user attempt to decrypt regular file\n");
                res = SHOULD_NOT_PERFORM_CRYPTO_ERR;
                goto out_free_ll;
            }
            
            // copying string to a new buffer for string tinkering
            size_t dec_file_path_len = strlen(current_node->file_path); 
            char new_dec_filepath[dec_file_path_len + strlen(".crdec")];
            strncpy(new_dec_filepath, current_node->file_path, sizeof(new_dec_filepath)); // copying string to avoid manipulating old string
            new_dec_filepath[sizeof(new_dec_filepath)-1] = '\0'; // ensuring string is NULL terminated
            
            // getting string from last dot (check if enc extension here)
            char *p_last_dot = strrchr(new_dec_filepath, '.');
            if (strcmp(p_last_dot, ".crenc") != 0) { // .crenc not at the end of the string
                fprintf(stderr, "ERROR: .crenc extension not at end of file location\n");
                res = SHOULD_NOT_PERFORM_CRYPTO_ERR;
                goto out_free_ll;
            }
            *p_last_dot = '\0'; // setting a NULL terminator where there was previously a .crenc extension

            // adding .crdec to end of file to avoid overwriting original file
            size_t remaining_space_dec_buf = sizeof(new_dec_filepath) - strlen(new_dec_filepath) - 1;
            strncat(new_dec_filepath, ".crdec", remaining_space_dec_buf);

            // decrypting file and storing at new filepath
            int dec_res = decrypt_file(current_node->file_path, new_dec_filepath, flags.password);
            if (dec_res != SUCCESS) {
                res = dec_res;
                goto out_free_ll;
            }
            printf("SUCCESS: Decrypted file stored at (%s)\n", new_dec_filepath);

            // moving to the next path in the linked list
            current_node = current_node->next; // could be NULL
        }
    } else {
        fprintf(stderr, "ERROR: unknown error occurred (dec_file and enc_file are both NULL but passed all if statements)\n");
        res = UNKNOWN_ERR;
        goto out_basic;
    }

    // removing old file if the --remove flag is on --> recommended to leave off for safety reasons
    if (flags.remove_old_flag && !flags.recursive_crypto_flag) {
        // ask user if they want to delete the old file if --remove is provided
        char usr_buf[8] = {'\t'}; // shouldn't need anymore than 1 char
        
        // checking which file is to be removed
        char *file_to_rm = NULL;
        if (flags.dec_file && !path_is_dir(flags.dec_file)) {
            file_to_rm = flags.dec_file;
        } else if (flags.enc_file && !path_is_dir(flags.enc_file)) {
            file_to_rm = flags.enc_file;
        } 

        // checking for remaining NULL as a result of some error
        if (!file_to_rm) {
            fprintf(stderr, "ERROR: unknown reason for remaining NULL when trying to remove file\n");
            res = NULL_ERR;
            goto out_free_ll;
        }

        // getting user input
        printf("CONFIRMATION: Remove old file (%s) on encryption/decryption (y/n)? ", file_to_rm); 
        char *usr_get_ret = fgets(usr_buf, sizeof(usr_buf), stdin);
        if (usr_get_ret == NULL) { // checking that user input is good
            fprintf(stderr, "ERROR: could not capture user input\n");
            res = INVALID_USER_INPUT;
            goto out_free_ll;
        }
        usr_buf[sizeof(usr_buf)-1] = '\0';
        char *last_newline = strrchr(usr_buf, '\n');
        if (last_newline) {
            *last_newline = '\0'; // null terminating the provided string
        }

        if (strcmp(usr_buf, "y") != 0) {
            fprintf(stderr, "ERROR: user provided --remove flag but did not confirm removal\n");
            res = INVALID_USER_INPUT;
            goto out_free_ll;
        }

        // remove the input file
        int rm_res = rm_file(file_to_rm);
        if (rm_res != SUCCESS) {
            res = rm_res;
            goto out_free_ll;
        }

        printf("SUCCESS: Removed (%s)\n", file_to_rm);
    }

out_free_ll:
    free_all_ll_mem(&p_path_LL_head);
out_basic:
    return res;
}
