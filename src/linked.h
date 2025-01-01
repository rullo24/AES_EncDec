#ifndef LINKED_H
#define LINKED_H

#include "status.h"

struct path_node {
    char file_path[MAX_PATH_LINUX];
    struct path_node *next;
};

int free_all_ll_mem(struct path_node **pp_path_LL_head);
int add_files_to_ll(struct path_node **pp_path_LL_head, char *crypto_filepath, bool recurse_flag, char encdec_option);
void DEBUG_print_ll_paths(struct path_node **pp_path_LL_head);

#endif