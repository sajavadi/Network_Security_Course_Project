/* 
 * File:   KeyGenerator.cpp
 * Author: Seyyed Ahmad Javadi
 *
 * Created on March 28, 2015, 1:50 PM
 */

#include <cstdlib>


#include <openssl/aes.h>
#include <openssl/rand.h>
#include<stdio.h>

using namespace std;

/*
 * 
 */
int main(int argc, char** argv) {

    if(argc != 2)
    {
        printf("please specify the key file name (only) \n");
    }
    
    FILE * key_file;
    unsigned char key[AES_BLOCK_SIZE];
     if(!RAND_bytes(key, AES_BLOCK_SIZE))
    {
        printf("Could not create random bytes.");
        exit(EXIT_FAILURE);
    }
    
    key_file = fopen(argv[1], "wb");
    
    fwrite(key, 1, AES_BLOCK_SIZE, key_file);
     
    
    return 0;
}

