#ifndef DECODE_H
#define DECODE_H

#include <stdio.h>
#include "types.h"

typedef struct _DecodeInfo{
    char *stego_image_fname;
    FILE *fptr_stego_image;

    char decoded_basename[256];  
} DecodeInfo;

Status read_and_validate_decode_args(char *argv[], DecodeInfo *decInfo);
Status do_decoding(DecodeInfo *decInfo);
Status open_decode_files(DecodeInfo *decInfo);

char decode_byte_from_lsb(FILE *fptr);
int decode_int_from_lsb(FILE *fptr);

#endif