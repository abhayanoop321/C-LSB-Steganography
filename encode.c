/*  Abhay P.A
    LSB Steganography
    30/10/2025
*/
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include "encode.h"
#include "types.h"
#include "common.h"
/* Function Definitions */

/* Get image size
 * Input: Image file ptr
 * Output: width * height * bytes per pixel (3 in our case)
 * Description: In BMP Image, width is stored in offset 18,
 * and height after that. size is 4 bytes
 */
uint get_image_size_for_bmp(FILE *fptr_image){
    uint width, height;
    // Seek to 18th byte
    fseek(fptr_image, 18, SEEK_SET);

    // Read the width (an int)
    fread(&width, sizeof(int), 1, fptr_image);
    printf("width = %u\n", width);

    // Read the height (an int)
    fread(&height, sizeof(int), 1, fptr_image);
    printf("height = %u\n", height);

    // Return image capacity
    return width * height * 3;
}

uint get_file_size(FILE *fptr){
    // Find the size of secret file data
    uint size;
    fseek(fptr, 0, SEEK_END);
    size = ftell(fptr);
    rewind(fptr);
    return size;
}

/*
 * Get File pointers for i/p and o/p files
 * Inputs: Src Image file, Secret file and
 * Stego Image file
 * Output: FILE pointer for above files
 * Return Value: e_success or e_failure, on file errors
 */

Status read_and_validate_encode_args(char *argv[], EncodeInfo *encInfo){
    char *ptr1 = strstr(argv[2], ".bmp");
    if (ptr1 == NULL || strcmp(ptr1, ".bmp") != 0){  //checks if the original image is having '.bmp' extension
        printf("Invalid Source File!\n");
        return e_failure;
    }
    encInfo->src_image_fname = malloc(strlen(argv[2]) + 1);  //allocate memory and store the name after validation
    strcpy(encInfo->src_image_fname, argv[2]);
    char *ptr2 = strstr(argv[3], ".txt");
    if (ptr2 == NULL || strcmp(ptr2, ".txt") != 0){  //validate extension of secret file (can be .txt, .sh or .c)
        ptr2=strstr(argv[3], ".sh");
        if(ptr2 == NULL || strcmp(ptr2, ".sh")!=0){
            ptr2=strstr(argv[3], ".c");
            if(ptr2 == NULL || strcmp(ptr2, ".c")!=0){
                printf("Invalid Secret File!\n");
                return e_failure;
            }
        }
    }
    strcpy(encInfo->extn_secret_file, ptr2); //After validating store into structure
    encInfo->secret_fname = malloc(strlen(argv[3]) + 1);
    strcpy(encInfo->secret_fname, argv[3]);
    if (argv[4] == NULL){
        encInfo->stego_image_fname = malloc(strlen("default.bmp") + 1);
        strcpy(encInfo->stego_image_fname, "default.bmp");
    }
    else{
        char *ptr3 = strstr(argv[4], ".bmp");
        if (ptr3 == NULL || strcmp(ptr3, ".bmp") != 0){
            printf("Invalid Destination File!\n");
            return e_failure;
        }
        encInfo->stego_image_fname = malloc(strlen(argv[4]) + 1);
        strcpy(encInfo->stego_image_fname, argv[4]);
    }

    return e_success;
}

Status open_files(EncodeInfo *encInfo){
    encInfo->fptr_src_image = fopen(encInfo->src_image_fname, "r");  //Open source image in read mode
    if(encInfo->fptr_src_image==NULL){  // Do Error handling
        perror("fopen");
        fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->src_image_fname);
        return e_failure;
    }
    encInfo->fptr_secret=fopen(encInfo->secret_fname, "r");  //Open secret file
    if(encInfo->fptr_secret==NULL){ 
        perror("fopen");
        fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->secret_fname);
        return e_failure;
    }
    encInfo->fptr_stego_image=fopen(encInfo->stego_image_fname, "w");  //Open destination file
    if(encInfo->fptr_stego_image==NULL){
        perror("fopen");
        fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->stego_image_fname);
        return e_failure;
    }
    return e_success;
}

Status check_capacity(EncodeInfo *encInfo){
    uint img_capacity=get_image_size_for_bmp(encInfo->fptr_src_image);  //Getting total byte size of source image
    encInfo->image_capacity=img_capacity;
    uint file_size=get_file_size(encInfo->fptr_secret);  //Getting total bytes of secret data
    encInfo->size_secret_file=(long)file_size;
    if(img_capacity>(strlen(MAGIC_STRING)*8)+(sizeof(int)*8)+(strlen(encInfo->extn_secret_file)*8)+(sizeof(int)*8)+(file_size*8)){
        return e_success;
    }  //Check if the source image has the capacity to encode the given data
    else{
        return e_failure;
    }
}

Status copy_bmp_header(FILE *fptr_src_image, FILE *fptr_dest_image){
    char header[54];
    rewind(fptr_src_image);
    if (fread(header, sizeof(char), 54, fptr_src_image) != 54){  //Copy first 54 bytes from source image to a char array
        printf("Error: Unable to read BMP header!\n");
        return e_failure;
    }
    if (fwrite(header, sizeof(char), 54, fptr_dest_image) != 54){  //Paste the same to destination image
        printf("Error: Unable to write BMP header!\n");
        return e_failure;
    }
    return e_success;
}
Status encode_magic_string(const char *magic_string, EncodeInfo *encInfo){
    char image_buffer[8];  //An 8 byte array to store 1 char at a time
    for(int i=0; i<strlen(magic_string); i++){
        char ch=magic_string[i];
        if (fread(image_buffer, sizeof(char), 8, encInfo->fptr_src_image) != 8){  //Read 8 bytes from source image
            printf("Error: Unable to read 8 bytes from source image while encoding extension!\n");
            return e_failure;
        }
        Status check1=encode_byte_to_lsb(ch, image_buffer);  //Function to encode 1 byte to LSB's of 8 bytes
        if(check1!=e_success){
            printf("Error Encoding Magic String!");
            return e_failure;            
        }
        if (fwrite(image_buffer, sizeof(char), 8, encInfo->fptr_stego_image) != 8){  //Write the encoded 8 bytes to destination image
            printf("Error: Unable to write 8 bytes into stego image while encoding extension!\n");
            return e_failure;
        }
    }
    if(ftell(encInfo->fptr_src_image)==ftell(encInfo->fptr_stego_image)){
        return e_success;
    }
    else{
        return e_failure;
    }
}
Status encode_secret_file_extn_size(int size, EncodeInfo *encInfo){
    char image_buffer[32];
    if (fread(image_buffer, sizeof(char), 32, encInfo->fptr_src_image) != 32){  //Copy 32 bytes from source image
        printf("Error: Unable to read 32 bytes from source image while encoding extension size!\n");
        return e_failure;
    }
    Status check1=encode_size_to_lsb(size, image_buffer);  //Encode the size of extension (4 bytes) to the LSB's of 32 bytes 
    if(check1!=e_success){
        printf("Error Encoding Secret File Extension Size!");
        return e_failure;            
    }
    if (fwrite(image_buffer, sizeof(char), 32, encInfo->fptr_stego_image) != 32){  //Write it to the destination image after encoding
        printf("Error: Unable to write 32 bytes into stego image while encoding extension size!\n");
        return e_failure;
    }
    if(ftell(encInfo->fptr_src_image)==ftell(encInfo->fptr_stego_image)){
        return e_success;
    }
    else{
        return e_failure;
    }
}

Status encode_secret_file_extn(const char *file_extn, EncodeInfo *encInfo){
    char image_buffer[8];  //An 8 byte array to store 1 char at a time
    int extn_len=strlen(file_extn);
    for(int i=0; i<extn_len; i++){
        if (fread(image_buffer, sizeof(char), 8, encInfo->fptr_src_image) != 8){  //Read 8 bytes from source image
            printf("Error: Unable to read 8 bytes from source image while encoding!\n");
            return e_failure;
        }
        Status check1=encode_byte_to_lsb(file_extn[i], image_buffer);  //Function to encode 1 byte to LSB's of 8 bytes
        if(check1!=e_success){
            printf("Error Encoding Secret File Extension!");
            return e_failure;            
        }
        if (fwrite(image_buffer, sizeof(char), 8, encInfo->fptr_stego_image) != 8){  //Write the encoded 8 bytes to destination image
            printf("Error: Unable to write 8 bytes into stego image while encoding!\n");
            return e_failure;
        }
    }
    if(ftell(encInfo->fptr_src_image)==ftell(encInfo->fptr_stego_image)){
        return e_success;
    }
    else{
        return e_failure;
    }
}

Status encode_secret_file_size(long file_size, EncodeInfo *encInfo){
    char image_buffer[32];  //Copy 32 bytes from source image
    if (fread(image_buffer, sizeof(char), 32, encInfo->fptr_src_image) != 32){  //Copy 32 bytes from source image
        printf("Error: Unable to read 32 bytes from source image while encoding!\n");
        return e_failure;
    }
    Status check1=encode_size_to_lsb(file_size, image_buffer);  //Encode the size of secret file (4 bytes) to the LSB's of 32 bytes 
    if(check1!=e_success){
        printf("Error Encoding Secret File Extension Size!");
        return e_failure;            
    }
    if (fwrite(image_buffer, sizeof(char), 32, encInfo->fptr_stego_image) != 32){  //Write it to the destination image after encoding
        printf("Error: Unable to write 32 bytes into stego image while encoding!\n");
        return e_failure;
    }
    if(ftell(encInfo->fptr_src_image)==ftell(encInfo->fptr_stego_image)){
        return e_success;
    }
    else{
        return e_failure;
    }
}

Status encode_secret_file_data(EncodeInfo *encInfo){
    if (fread(encInfo->secret_data, sizeof(char), encInfo->size_secret_file, encInfo->fptr_secret)  //Read the secret data
        != encInfo->size_secret_file){
        printf("Error: Unable to read %lu bytes from secret file!\n", encInfo->size_secret_file);
        return e_failure;
    }
    char image_buffer[8];
    for(int i=0; i<encInfo->size_secret_file; i++){  //For loop to encode each character
        char ch=encInfo->secret_data[i];
        if (fread(image_buffer, sizeof(char), 8, encInfo->fptr_src_image) != 8){  //Copy 8 bytes from source image
            printf("Error: Unable to read 8 bytes from source image while encoding secret file data!\n");
            return e_failure;
        }
        Status check1=encode_byte_to_lsb(ch, image_buffer);  //Function to encode each a byte to LSB's of 8 bytes
        if(check1!=e_success){
            printf("Error Encoding Secret File Data!");
            return e_failure;            
        }
        if (fwrite(image_buffer, sizeof(char), 8, encInfo->fptr_stego_image) != 8){  //Write the encoded bytes to the destination image
            printf("Error: Unable to write 8 bytes into stego image while encoding secret file data!\n");
            return e_failure;
        }
    }
    if(ftell(encInfo->fptr_src_image)==ftell(encInfo->fptr_stego_image)){
        return e_success;
    }
    else{
        return e_failure;
    }
}

Status copy_remaining_img_data(FILE *fptr_src, FILE *fptr_dest){
    char buffer[1024];
    int bytes_read;
    while((bytes_read=fread(buffer, sizeof(char), 1024, fptr_src)) > 0){  //Copy the remaining data directly to the destination image without any encoding
        if(fwrite(buffer, sizeof(char), bytes_read, fptr_dest)!=bytes_read){
            printf("Error: Unable to write remaining image data!\n");
            return e_failure;
        }
    }
    return e_success;
}

Status encode_byte_to_lsb(char data, char *image_buffer){
    for(int bit=0; bit<8; bit++){  //Clear LSB of each byte of sorce and store the bits from char 
        char bit_val=(data>>(7-bit))&1;
        image_buffer[bit]=(image_buffer[bit]&0xFE)|bit_val;
    }
    return e_success;        
}

Status encode_size_to_lsb(int size, char *imageBuffer){
    for(int bit=0; bit<32; bit++){  //Clear LSB's of 32 bytes and store each bits from an integer value
        char bit_val=(size>>(31-bit))&1;
        imageBuffer[bit]=(imageBuffer[bit] & 0xFE)|bit_val;
    }
    return e_success;
}

Status do_encoding(EncodeInfo *encInfo){
    Status check1=open_files(encInfo);  //Function to open required files
    if(check1==e_failure){
        printf("Error Opening Files!");
        return e_failure;
    }
    else{
        printf("Files Opened Succesfully\n");
    }
    Status check2=check_capacity(encInfo);  //Check if enough capacity is there in source image
    if(check2==e_failure){
        printf("Image Capacity Not Sufficient!\n");
        return e_failure;
    }
    Status check3=copy_bmp_header(encInfo->fptr_src_image, encInfo->fptr_stego_image);  //Copying basic header
    if(check3==e_failure){
        printf("Error Copying Header File!\n");
        return e_failure;
    }
    else{
        printf("Successfully Copied Header Files\n");
    }
    Status check4=encode_magic_string(MAGIC_STRING, encInfo);  //Encode magic string
    if(check4==e_failure){
        printf("Error Encoding Magic String!\n");
        return e_failure;
    }
    else{
        printf("Encoded Magic String Successfully\n");
    }
    Status check5=encode_secret_file_extn_size(strlen(encInfo->extn_secret_file), encInfo);  //Encode size of extension of secret file
    if(check5==e_failure){
        printf("Error Encoding Secret File Extension Size!\n");
        return e_failure;
    }
    else{
        printf("Encoded Secret File Extension Size Successfully\n");
    }
    Status check6=encode_secret_file_extn(encInfo->extn_secret_file, encInfo);  //Encode the extension
    if(check6==e_failure){
        printf("Error Encoding Secret File Extension!\n");
        return e_failure;
    }
    else{
        printf("Encoded Secret File Extension Successfully\n");
    }
    Status check7=encode_secret_file_size(encInfo->size_secret_file, encInfo);  //Encode the size of secret data
    if(check7==e_failure){
        printf("Error Encoding Secret File Data!\n");
        return e_failure;
    }
    else{
        printf("Encoded Secret File Data Successfully\n");
    }
    Status check8=encode_secret_file_data(encInfo);  //Encode the secret data
    if(check8==e_failure){
        printf("Error Encoding Secret File Data!\n");
        return e_failure;
    }
    else{
        printf("Encoded Secret File Data Successfully\n");
    }
    Status check9=copy_remaining_img_data(encInfo->fptr_src_image, encInfo->fptr_stego_image);  //Copy rest of the data 
    if(check9==e_failure){
        printf("Error Encoding Remaining Data!\n");
        return e_failure;
    }
    else{
        printf("Encoded Remaining Data Successfully\n");
    }
    return e_success;
}
