/*  Abhay P.A
    LSB Steganography
    30/10/2025
*/
#include<stdio.h>
#include<string.h>
#include "encode.h"
#include "decode.h"
#include "types.h"

OperationType check_operation_type(char *);

int main(int argc, char *argv[]){
    if(argc>=3){
        OperationType check=check_operation_type(argv[1]); //check if the user wants to encode or decode
        if(check==e_encode){
            if(argc<4){  //if no: of arguments are not correct, print error and expected input
                printf("Usage: ./a.out -e <src.bmp> <secret.txt> [output.bmp]\n");
                return 0;
            }
            EncodeInfo encInfo;
            if(read_and_validate_encode_args(argv, &encInfo)==e_success){  //validate each arguments, ie; their extension for encoding
                if(do_encoding(&encInfo)==e_success){
                    printf("Encoding Successful\n");
                }
                else{
                    printf("Error Encoding!\n");
                }
            }
            else{
                printf("Invalid Encode Arguments!\n");
            }
        }
        else if(check == e_decode)
        {
            DecodeInfo decInfo;
            if(read_and_validate_decode_args(argv, &decInfo)==e_success){  //validate each arguments, ie; their extension for decoding
                if (do_decoding(&decInfo)==e_success){
                    printf("Decoding Successful\n");
                }
                else{
                    printf("Decoding Failed!\n");
                }
            }
            else{
                printf("Invalid Decode Arguments!\n");
            }
        }
        else{
            printf("Unsupported Option! Use -e for encode or -d for decode\n");
        }
    }
    else{
        printf("Insufficient Arguments!\n");
        printf("Usage:\n");
        printf("./a.out -e <src.bmp> <secret.txt> [output.bmp]\n");
        printf("./a.out -d <stego.bmp> [output_name]\n");
    }
    return 0;
}

OperationType check_operation_type(char *symbol){
    if(!(strcmp(symbol, "-e"))){  //if user entered -e return e_encode
        return e_encode;
    }
    else if(!(strcmp(symbol, "-d"))){  //if user entered -d return e_decode
        return e_decode;
    }
    else{
        return e_unsupported;
    }
}
