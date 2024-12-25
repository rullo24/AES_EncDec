#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <openssl/evp.h>
#include <stdio.h>
#include "status.h"

int encrypt_file(const char *input_filename, const char *output_filename, const char *password);

#endif