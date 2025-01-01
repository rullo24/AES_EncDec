#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "linked.h"
#include "utils.h"

int add_to_path_ll(struct path_node **pp_path_LL_head, const char *path) {
    int res = SUCCESS;   

    // check if the provided path is an actual file
    bool file_exists_res = regular_file_exists(path);
    if (!file_exists_res) {
        res = file_exists_res;
        goto out;
    }
    
    // HEAP allocated memory --> to be freed on program end
    struct path_node *p_new_node = malloc(sizeof(struct path_node)); 
    if (!p_new_node) {
        fprintf(stderr, "ERROR: failed to alloc memory for a new node\n");
        res = ENOMEM;
        goto out;
    }
    
    // updating new node variables
    p_new_node->next = NULL; // will be the new last (does not need a next)
    strncpy(p_new_node->file_path, path, sizeof(p_new_node->file_path)); // copying the path to the node
    p_new_node->file_path[sizeof(p_new_node->file_path)-1] = '\0'; // setting last character to a NULL byte just in case

    // adding new node to the existing linked list
    if (!(*pp_path_LL_head)) { // NULL currently
        *pp_path_LL_head = p_new_node; // HEAD pointing to the new node
        return res;
    }

    // iterating to end of LL
    struct path_node *current_node = *pp_path_LL_head; // starting from first node of LL
    while (current_node->next) {
        current_node = current_node->next; // moving to next node
    }
    
    // setting new last node
    current_node->next = p_new_node;
    
out:
    return res;
}

int free_all_ll_mem(struct path_node **pp_path_LL_head) {
    int res = SUCCESS;   

    if (!(*pp_path_LL_head)) { // empty linked list
        goto out;
    }

    struct path_node *current_node = *pp_path_LL_head; // start by pointing to head
    struct path_node *next_node = NULL;

    // iterating over all available nodes
    while (current_node) {
        next_node = current_node->next;
        free(current_node);
        current_node = next_node;
    }

    // avoid dangling ptr 
    *pp_path_LL_head = NULL;

out:
    return res;
}

int add_all_dir_files_to_ll(struct path_node **pp_path_LL_head, const char *directory, char encdec_option) {
    // init necessary variables
    int res = SUCCESS;
    struct dirent *entry;

    // checking if user parsed a directory
    if (!path_is_dir(directory)) {
        fprintf(stderr, "ERROR: provided a non-directory to a directory function");
        res = NON_DIRECTORY_ERR;
        goto out;
    }

    // creating a pointer for iterating over UNIX directories
    DIR *p_dir_linux = opendir(directory);
    if (!p_dir_linux) {
        fprintf(stderr, "ERROR: failed to open the directory (%s)\n", directory);
        res = FILE_OPEN_ERR;
        goto out;
    }

    // iterating over all files within the provided directory
    while ((entry = readdir(p_dir_linux)) != NULL) {
        char abs_filepath_buf[MAX_PATH_LINUX] = {'\0'};
        
        // ensuring that the filepath is valid
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue; // skipping these
        }

        // getting absolute filepath of file
        strncpy(abs_filepath_buf, directory, sizeof(abs_filepath_buf)); // copying to temp buffer
        
        // adding backslash in between the filename and the directory absolute path
        size_t remaining_space_abs_buf = sizeof(abs_filepath_buf) - strlen(abs_filepath_buf) - 1;
        strncat(abs_filepath_buf, "/", remaining_space_abs_buf);

        // adding the filename after the new backslash
        remaining_space_abs_buf--;
        strncat(abs_filepath_buf, entry->d_name, remaining_space_abs_buf); // concatenating the filename to the absolute directory path

        // skipping over directories
        if (!regular_file_exists(abs_filepath_buf)) {
            continue; // skipping over files that aren't regular (including directories)
        }

        // need to make sure that it makes sense to encrypt or decrypt this file
        if (encdec_option == 'e') {
            
            // checking if file is already encrypted --> skip encrypted files
            if (substring_is_in_phrase(abs_filepath_buf, ".crenc")) {
                continue;
            }

        } else if (encdec_option == 'd') {

            // checking the file is not encrypted --> skipping non-encrypted files
            if (!substring_is_in_phrase(abs_filepath_buf, ".crenc")) { // non-encrypted
                continue; // don't decrypt
            }

        } else {
            fprintf(stderr, "ERROR: invalid encdec_option char provided to add_all_dir_files_to_ll\n");
            res = INVALID_USER_INPUT;
            goto out_dir_close;
        }

        // adding the absolute filepath to the LL
        int ll_add_res = add_to_path_ll(pp_path_LL_head, abs_filepath_buf);
        if (ll_add_res != SUCCESS) {
            res = ll_add_res;
            goto out_dir_close;
        }
    }

out_dir_close:
    closedir(p_dir_linux);
out:
    return res;
}

int add_files_to_ll(struct path_node **pp_path_LL_head, char *crypto_filepath, bool recurse_flag, char encdec_option) {
    int res = SUCCESS;

    // iterate over all files recursively (if possible)
    if (recurse_flag) {
        // checking if provided path is directory (error if not)
        if (!path_is_dir(crypto_filepath)) {
            fprintf(stderr, "ERROR: provided a non-dir path but wanted recursive encryption\n");
            res = INVALID_PARSE_ERR;
            goto out;
        }

        // adding all files to linked list via readdir
        int recursive_add_res = add_all_dir_files_to_ll(pp_path_LL_head, crypto_filepath, encdec_option);
        if (recursive_add_res != SUCCESS) {
            res = recursive_add_res;
            goto out;
        }

    } else { // acting on singular file
        int ll_add_res = add_to_path_ll(pp_path_LL_head, crypto_filepath);
        if (ll_add_res != SUCCESS) {
            res = ll_add_res;
            goto out;
        }
    }

out: 
    return res;
}

void DEBUG_print_ll_paths(struct path_node **pp_path_LL_head) {
    if (!(*pp_path_LL_head)) {
        printf("failed to print the nodes\n");
        return;
    }

    struct path_node *p_current_node = *pp_path_LL_head;
    while (p_current_node) {
        printf("LOC: %s\n", p_current_node->file_path);
        p_current_node = p_current_node->next;
    }
}
