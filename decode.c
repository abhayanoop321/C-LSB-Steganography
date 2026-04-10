/*  Abhay P.A
    LSB Steganography
    30/10/2025
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decode.h"
#include "common.h"   
#include "types.h"

char decode_byte_from_lsb(FILE *fptr)
{
    unsigned char buffer[8];
    if (fread(buffer, sizeof(char), 8, fptr)!=8){  //Read 8 bytes from source to a buffer array
        return 0;
    }
    unsigned char ch=0;
    for (int i=0; i<8; i++){  //Read each bit and shift 8 times to get a single char
        ch=(ch << 1) | (buffer[i] & 1);
    }
    return ch;
}

int decode_int_from_lsb(FILE *fptr){
    unsigned char buffer[32];
    if (fread(buffer, sizeof(char), 32, fptr)!=32){  //Read the 32 bytes storing the int value
        return -1;
    }
    int value=0;
    for (int i=0; i<32; i++){
        value=(value << 1) | (buffer[i] & 1);  //Read the 32 bits from LSB's of 32 bytes to the integer value
    }
    return value;
}

Status read_and_validate_decode_args(char *argv[], DecodeInfo *decInfo)
{
    if (argv[2]==NULL){  //Return failure if the name of file to be decoded is not given
        return e_failure;
    }
    char *ptr=strstr(argv[2], ".bmp");  //Verify if the file extension is .bmp
    if (ptr==NULL || strcmp(ptr, ".bmp")!=0){
        return e_failure;
    }
    decInfo->stego_image_fname=malloc(strlen(argv[2]) + 1);  //Allocate memory to store the file name
    strcpy(decInfo->stego_image_fname, argv[2]);
    if (argv[3]==NULL){  //If output file name is not given save the name 'output' as default
        strcpy(decInfo->decoded_basename, "output");
    }
    else{
        strcpy(decInfo->decoded_basename, argv[3]);  //If given check if any extension is given and remove it
        char *dot=strchr(decInfo->decoded_basename, '.');
        if (dot!=NULL){
            *dot='\0';
        }
    }
    return e_success;
}

Status open_decode_files(DecodeInfo *decInfo){  //Open the file to decode in read mode
    decInfo->fptr_stego_image=fopen(decInfo->stego_image_fname, "r");
    if (decInfo->fptr_stego_image==NULL)
    {
        perror("fopen");
        fprintf(stderr, "ERROR: Unable to open file %s\n", decInfo->stego_image_fname);
        return e_failure;
    }
    return e_success;
}

Status do_decoding(DecodeInfo *decInfo)
{
    if (open_decode_files(decInfo)==e_failure){  //Call function to open file
        return e_failure;
    }
    fseek(decInfo->fptr_stego_image, 54, SEEK_SET);
    int magic_len=strlen(MAGIC_STRING);
    char magic[5];
    for (int i=0; i<magic_len; i++){  //Read magic string bytes from the source
        magic[i]=decode_byte_from_lsb(decInfo->fptr_stego_image);
    }
    magic[magic_len]='\0';
    if (strcmp(magic, MAGIC_STRING)!=0){  //Compare the magic strings match
        printf("Not a valid stego file! Magic string mismatch!\n");
        return e_failure;
    }
    printf("Magic string verified: %s\n", magic);
    int extn_size=decode_int_from_lsb(decInfo->fptr_stego_image);  //Function to decode extension size
    printf("Extension size: %d\n", extn_size);
    char extn[10];
    for (int i=0; i<extn_size; i++){
        extn[i]=decode_byte_from_lsb(decInfo->fptr_stego_image);  //Decode the extension byte by byte
    }
    extn[extn_size]='\0';
    printf("Decoded extension: %s\n", extn);
    int secret_size=decode_int_from_lsb(decInfo->fptr_stego_image);  //Decode the size of secret data
    printf("Secret file size: %d bytes\n", secret_size);
    char *data=malloc(secret_size + 1);
    for (int i=0; i<secret_size; i++){
        data[i]=decode_byte_from_lsb(decInfo->fptr_stego_image);  //Decode each byte of secret data
    }
    data[secret_size]='\0';
    char final_name[300];
    sprintf(final_name, "%s%s", decInfo->decoded_basename, extn);
    FILE *out=fopen(final_name, "w");
    fwrite(data, sizeof(char), secret_size, out);
    fclose(out);
    printf("Decoded file written: %s\n", final_name);
    printf("Data: %s\n", data);
    free(data);
    fclose(decInfo->fptr_stego_image);
    return e_success;
}
