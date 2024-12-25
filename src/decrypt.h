#ifndef DECRYPT_H
#define DECRYPT_H

#include <openssl/evp.h>
#include <stdio.h>
#include "status.h"

int decrypt_file(const char *input_filename, const char *output_filename, const char *password);

#endif