/* 
 * File:   pbproxy.cpp
 * Author: Seyyed Ahmad Javadi
 *
 * Created on March 19, 2015, 12:11 PM
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>	
#include <sys/socket.h>
#include <arpa/inet.h>	
#include <unistd.h>	
#include <pthread.h>
#include <netdb.h>	
#include <ctype.h>
#include <iostream>


#include <openssl/aes.h>
#include <openssl/rand.h>



#define LOGFILE	"/tmp/pbproxy.log"     // error messages will be written to this file
#define bufSize 1440 
#define cipherBufSize 1456 
#define Max_Connections 10
#define Max_IP_Length 15
//this is the structure used for keeping encryption and decryption state
struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

//this structure is used for passing two sockets to new thread
struct pbproxy_server_sockets
{
    int client_socket;
    int server_socekt;
};

 
void log (const char *message);    // logs a message to LOGFILE
void logError (const char *message); // logs a message; 



int encrypt(char * keyfile, unsigned char * iv, struct ctr_state *enc_state, char * inbuffer, int inBufSize , char * outbuffer);
int decrypt(char * keyfile, unsigned char * iv, struct ctr_state *dec_state, char * inbuffer, int inBufSize, char * outbuffer);
void clientProxy(char * keyfile, char * dstUrl, int dstPort);
void serverProxy (char * keyfile, int inboundPort);
void * connectionHandler(void *);
void * receiveFromClientSend2Server(void *);
void * receiveFromServerWrtie2Stdout(void *);
int HostNameToIP(char *hostname , char *ip);
int sendData(int  , const char * , int );
int init_ctr(struct ctr_state *state, const unsigned char iv[16]);


//We need this information in all server side threads!
char * dstUrl = NULL;
int dstPort = 0;
char * keyFile;


int main(int argc,  char ** argv) 
{
   
    int lflag = 0;
    int kflag = 0;
    
    int inboundPort;
     
    int c;	
    // Here I use getopt function to read the program input options!
    while ((c = getopt (argc, argv, "l:k:")) != -1)
    {
        switch (c)
        {
            case 'l':
                lflag = 1;
                //printf("%s \n", optarg); 
                inboundPort = atoi(optarg);
                break;
            case 'k':
                kflag = 1;
                //printf("%s \n", optarg);
                keyFile= optarg;
                break;
            default:
                printf("Error!!! Unknown Parameters!!!\n");
                return -1;
        }
    }    
    
    
    if (argv[optind] != NULL)
	dstUrl = argv[optind];
    c = optind + 1;
    if(argv[c] != NULL)
        dstPort =atoi(argv[c]);
   
    if(kflag == 0)
    {
        printf("You should specify keyfile\n");
        logError("You should specify keyfile\n");
        exit(EXIT_FAILURE);
    }
    
    if(dstUrl == NULL)
    {
        printf("You should specify destination url\n");
        logError("You should specify destination url\n");
        exit(EXIT_FAILURE);   
    }    
    
    if(dstPort == 0)
    {
        printf("You should specify destination port\n");
        logError("You should specify destination port\n");
        exit(EXIT_FAILURE);   
    } 
    
    
    if(lflag == 0 )
    {
        clientProxy(keyFile,dstUrl, dstPort);
    }
    else if (lflag == 1)
    {
        serverProxy(keyFile,inboundPort);
    }
    
     
    return 0;
}

// Send bufS bytes to network through socket_desc

int sendData(int socket_desc, const char * buf, int bufS)
{
    int len=0;
    int bytesSent;
    while(len<bufS){
        
	//if((bytesSent=send(socket_desc,buf+len,bufS-len,0)) < 0 )
        if((bytesSent=write(socket_desc,buf+len,bufS-len)) < 0 )
        {
            return -1;
        }
        if(bytesSent == 0)
        {
            return 0; 
        }    
        len += bytesSent;
    }
    return 1; 
}

// Writes bufS bytes in stdout

int writeDataToStdout(const char * buf, int bufS)
{
    int len=0;
    int bytesWrote=0;
    while(len<bufS){
	if((bytesWrote=write(1,buf+len,bufS-len)) < 0 )
        {
            return -1;
        }
        if(bytesWrote == 0)
        {
            return 0;
        }    
        len += bytesWrote;
    }
    return 1; 
}

/* This function is the implementation of client side pbporxy. 

*/


void clientProxy(char * keyfile, char * dstUrl, int dstPort)
{
    int tmp;
    int pbproxy_socket;
    char pbproxy_server_ip[Max_IP_Length];
    struct sockaddr_in pbproxy_server;
    char cipherBuf[cipherBufSize];
    char inBuf[bufSize];
    int numOfBytes = 0;
   
    //HostNameToIP calls gethostbyname on dstUrl and return the first result
    //In the case that dstUrl is a valid IP address, no lookup i performed by
    //gethostbyname and the output will be the same IP address
    if(HostNameToIP(dstUrl, pbproxy_server_ip) == 0)
    {
        logError("Client: not valid IP address or error in dstUrl --> IP Address");
        return;
    }
   
    //filling pbproxy server side info
    pbproxy_server.sin_addr.s_addr = inet_addr(pbproxy_server_ip);
    pbproxy_server.sin_family = AF_INET;
    pbproxy_server.sin_port = htons(dstPort);
    
    
   
    pbproxy_socket = socket(AF_INET , SOCK_STREAM , 0);
     
    if (pbproxy_socket == -1)
    {
        logError("Client: Error in creating client socket");
        return;
    }
  
    //Connect to pbproxy_s
    if (connect(pbproxy_socket , (struct sockaddr *)&pbproxy_server , sizeof(pbproxy_server)) < 0)
  {
        logError("Client: Error in connecting to pbproxy_s");
        return;

    }
    
    
    //Creating Initial Vector and send it to pbproxy_s
    //This IV is used for encrypting traffic from pbproxy_c --> pbproxy_s
    //Also it is used for decrypting receiving traffic in pbproxy_s
    
    unsigned char  iv[AES_BLOCK_SIZE];   
    
    if(!RAND_bytes(iv, AES_BLOCK_SIZE))
    {
        logError("Could not create random bytes.");
        return;    
    }
    
    if(sendData(pbproxy_socket , (char *) iv , AES_BLOCK_SIZE) < 0)
    {
        logError("Client: Error in sending data to pbproxy_s");
        close(pbproxy_socket);
        return;
    }
    
    //Initiate encryption state
    
    struct ctr_state enc_state;
    init_ctr(&enc_state, iv);
    
    
    // receiver_thread is responsible for receiving packets from pbproxy_s
    // the input parameter for this thread is the socket between pbproxy_c and pbproxy_s
    pthread_t receiver_thread;
    int * thread_desc = (int *) malloc(sizeof(int));
    *thread_desc = pbproxy_socket;
    if( pthread_create( & receiver_thread , NULL ,  receiveFromServerWrtie2Stdout , (void*) thread_desc) < 0)
    {
        logError("Client: Error in creating thread");
        close(pbproxy_socket);
        return;
    }
    
    //Sending packets in a while(1) loop to pbproxy_s
    
    while(1)
    {
        //Read inBuf bytes from stdin
        if((numOfBytes = read(0, inBuf, bufSize))<0)
        {
            logError("Client: Error in reading from stdin");
            close(pbproxy_socket);
            return;
        }
        
        if(numOfBytes == 0)
        {
            logError("Client: Connection is closed");
            close(pbproxy_socket);
            return;
        }
        
        
        if(numOfBytes > 0)
        {
            
            //Encrypt the inbuf
            numOfBytes = encrypt(keyfile, iv, &enc_state, inBuf, numOfBytes, cipherBuf);
            
            if(numOfBytes < 0)
            {
                logError("Client: Error in encrypting data");
                close(pbproxy_socket);
                return;
            }    
            //Send the encrypted data to client_s
            if( (numOfBytes = sendData(pbproxy_socket , cipherBuf , numOfBytes)) < 0)
            {
                logError("Client: Error in sending data to pbproxy_server");
                close(pbproxy_socket);
                return;
            }
            if(numOfBytes == 0)
            {
                logError("Client: connection is closed");
                close(pbproxy_socket);
                return;
            }    
        }
        
    
    }
    
    close(pbproxy_socket);
    
}

//This function which is executed as a separate thread is responsible for 
//receiving traffic from pbproxy_s, decrypt it and write it to stdout!!

void * receiveFromServerWrtie2Stdout(void * cleint_socket)
{
    char pbproxy_server_response[cipherBufSize];
    char plainText[cipherBufSize];
    int numOfBytes;
    int pbproxy_socket = *(int*)cleint_socket;
    
    
    //The first step  is to receive IV from the pbproxy_s
    //We need IV to decrypt packet come from pbproxy_s
    
    unsigned char  iv[AES_BLOCK_SIZE];
    if((numOfBytes = read(pbproxy_socket, iv , AES_BLOCK_SIZE))<0)
    {
            logError("Client: Error in receiving iv from pbproxy server");
            close(pbproxy_socket);
            free(cleint_socket);
            return NULL;
    }
    if(numOfBytes != 16)
    {
        logError("Client: received iv length should be 16 bytes");
        close(pbproxy_socket);
        free(cleint_socket);
        return NULL;   
    }    
    
    //Initiate decryption state
    
    struct ctr_state dec_state;
    init_ctr(&dec_state, iv);
    
     while(1)
    {
        
        //Read bufSize from the socket
        if((numOfBytes = read(pbproxy_socket, pbproxy_server_response , bufSize))<0)
        {
            logError("Client: Error in receiving data from pbproxy_s");
            close(pbproxy_socket);
            free(cleint_socket);
            return  NULL;
        }
        else if (numOfBytes == 0)
        {
            logError("Client: connection is closed");
            close(pbproxy_socket);
            free(cleint_socket);
            return  NULL;
        }    
        else 
        {
           //Decrypt the data and wrtie plainText to stdout
           numOfBytes = decrypt(keyFile,iv, &dec_state, pbproxy_server_response, numOfBytes, plainText);

           if(numOfBytes < 0 )
           {
               logError("Client: Error in decryption function");
               close(pbproxy_socket);
               free(cleint_socket);
               return  NULL;
           }
           
           if((numOfBytes = writeDataToStdout(plainText, numOfBytes))<0) 
           {
               logError("Client: error in writing to stdout");
               close(pbproxy_socket);
               free(cleint_socket);
               return  NULL;
           }
           
           if(numOfBytes == 0)
           {
                logError("Client: write to stdout returned zero");
                close(pbproxy_socket);
                free(cleint_socket);
                return  NULL;
           }   
            // write(1,pbproxy_server_response, numOfBytes);
            // printf("%d bytes write to stdout \n", tmp );
        }
    }
    
}


//This function is the server side implementation for plugboard proxy

void serverProxy (char * keyfile, int inboundPort)
{
    int pbproxy_socket_desc, client_desc, * thread_desc;
    struct sockaddr_in pbproxy_server, pbproxy_client;
    int tmp;
    
    //Creating a socket and binding it to a specified port!!
    
    if((pbproxy_socket_desc = socket(AF_INET , SOCK_STREAM , 0)) == -1 )
    {
        //logError("Server: Error in creating a socket");
        return;

    }
     
    pbproxy_server.sin_family = AF_INET;
    pbproxy_server.sin_addr.s_addr = INADDR_ANY;
    pbproxy_server.sin_port = htons( inboundPort );
     
    if( bind(pbproxy_socket_desc,(struct sockaddr *)&pbproxy_server , sizeof(pbproxy_server)) < 0)
    {
        return;
    }
    
    //Listen to new connections
    //We simply 
    listen(pbproxy_socket_desc , Max_Connections);
     
    
    tmp = sizeof(struct sockaddr_in);
    while(1)
    {        
        //accept new connection
        
        client_desc = accept(pbproxy_socket_desc, (struct sockaddr *)&pbproxy_client, (socklen_t*)&tmp);
        
        if (client_desc < 0 )
        {
            printf("Server: accept failed\n");
        }
        
        else
        {
            printf("new connection \n");
            
            //Creating a new thread for the new connection
        
            pthread_t per_client_thread;
            thread_desc = (int *) malloc(sizeof(int));
            *thread_desc = client_desc;
        
            if( pthread_create( & per_client_thread , NULL ,  connectionHandler , (void*) thread_desc) < 0)
            {
               printf("Server: Error in creating thread for new connection\n");
               close(client_desc);
            }
        } 
        
    }
    
    close(pbproxy_socket_desc);
}


//This function is responsible for handling new connection to pbproxy_s


void *connectionHandler(void *socket_desc)
{
   
  
    int client_socket = *(int*)socket_desc;
    int server_socket;
    char sshd_ip[Max_IP_Length];
    struct sockaddr_in pbproxy_server;
    char server_response[bufSize];
    char cipherText[cipherBufSize];
    int numOfBytes = 0;
    
    
    //It first creates a IV and send to the pbproxy_c
    //This IV is used in the encryption process of traffic from pbproxy_s --> pbproxy_c
    
    unsigned char iv [AES_BLOCK_SIZE];   
    
    if(!RAND_bytes(iv, AES_BLOCK_SIZE))
    {
        printf("Server: Could not create random bytes.\n");
        close(client_socket);
        free(socket_desc);
        printf("pbproxy_s <---> sshd thread is finished\n");
        return NULL;    
    }
    
    if(sendData(client_socket , (char *) iv , AES_BLOCK_SIZE) < 0)
    {
        printf("Server: Error in sending data to client\n");
        close(client_socket);
        free(socket_desc);
        printf("pbproxy_s <---> sshd thread is finished\n");
        return NULL; 
    }
    //Initiate encryption state
    struct ctr_state enc_state;
    init_ctr(&enc_state, iv);
    
    
    //Converting dstUrl to IP address!! 
    //For a valid input address, the output will be same as input
    if(HostNameToIP(dstUrl, sshd_ip) == 0)
    {
        printf("Server: Error in dstUrl --> IP Address\n");
        close(client_socket);
        free(socket_desc);
        printf("pbproxy_s <---> ssd thread is finished\n");
        return NULL;
    }
    
    
    //Create a socket used for connecting to sshd
    
    server_socket = socket(AF_INET , SOCK_STREAM , 0);
     
    if (server_socket == -1)
    {
        printf("Server: Error in creating  socket to connect to sshd\n");
        close(client_socket);
        free(socket_desc);
        printf("pbproxy_s <---> sshd thread is finished\n");
        return NULL;
    }
    
    //Setup a connection to sshd
    
    pbproxy_server.sin_addr.s_addr = inet_addr(sshd_ip);
    pbproxy_server.sin_family = AF_INET;
    pbproxy_server.sin_port = htons(dstPort);
 
    //Connect to remote sshd
    if (connect(server_socket , (struct sockaddr *)&pbproxy_server , sizeof(pbproxy_server)) < 0)
    {
     	printf("Server: Error in connecting to sshd\n");
        close(client_socket);
        free(socket_desc);
        printf("pbproxy_s <---> sshd thread is finished\n");
        return NULL;
    }
     
    //Here we create another thread that is responsible for receiving data
    //from pbproxy_c and send it to the pbproxy_s
    //Current thread does receiving from pbproxy_s and sending it back to pbproxy_c
    
    struct pbproxy_server_sockets * sockets = (struct pbproxy_server_sockets *)  malloc(sizeof(pbproxy_server_sockets )); 
    
    sockets->client_socket = client_socket;
    sockets->server_socekt= server_socket;
    pthread_t receiveSendThread;
    if( pthread_create( & receiveSendThread , NULL ,  receiveFromClientSend2Server , (void*) sockets) < 0)
    {
                printf("Server: Error in creating thread\n");
                close(server_socket);
                close(client_socket);
                free(socket_desc);
                printf("pbproxy_s <---> sshd thread is finished\n");
                return NULL;
    }
   
    while(1)
    {
       
        //Receive data from sshd
        
        if((numOfBytes = read(server_socket, server_response , bufSize))<0)
        {
            printf("Server: Error in receiving data from ssh server\n");
            close(server_socket);
	    close(client_socket);
            free(socket_desc);
            printf("sshd ---> pbproxy_s thread is finished\n");
            return NULL;
        }
        //Check weather connection is closed? 
        if(numOfBytes == 0)
        {
            printf("Server: pbproxy_s to sshd is closed\n");
            close(server_socket);
	    close(client_socket);
            free(socket_desc); 
            printf("sshd ---> pbproxy_s thread is finished\n");
            return NULL;
        }    
         if(numOfBytes > 0)
        {
         
            //Encrypt data
            numOfBytes = encrypt(keyFile, iv, &enc_state, server_response, numOfBytes, cipherText); 
         
            
            if(numOfBytes < 0)
            {
                printf("Server: error in encryption function\n");
                close(server_socket);
                close(client_socket);
                free(socket_desc);
                printf("Encryption error: sshd ---> pbproxy_s thread is finished\n");
                return NULL;
            }
            
            
            //Send data to pbproxy_c
            if((numOfBytes = sendData(client_socket, cipherText, numOfBytes))<0)
            {

                printf("Server: Error in sending data to pbproxy client\n");
		close(client_socket);                
		close(server_socket);
                free(socket_desc);
                printf("sshd ---> pbproxy_s thread is finished\n");
                return NULL; 
            }
           if(numOfBytes == 0)
           {
                printf("Server: client socket is closed\n");
		close(client_socket);                
		close(server_socket);
                free(socket_desc);
                printf("sshd ---> pbproxy_s thread is finished\n");
                return NULL; 
           }    
            //printf("%d bytes sent to client \n", numOfBytes );
        }
    }
    
    close(client_socket);
    free(socket_desc);
    close(server_socket); 
    return NULL;
}


//This function is ran as separate thread to receive packers from pbproxy_c
//And deliver them to sshd

void * receiveFromClientSend2Server(void * sockets){
    

    
    char inBuf[cipherBufSize];
    char plainText[cipherBufSize];
    int numOfBytes = 0;
    
    struct pbproxy_server_sockets * s =  (struct pbproxy_server_sockets *) sockets;
    
    int client_socket = s->client_socket;
    
    int server_socket = s->server_socekt;
    
    //Read IV that is sent by pbproxy_c in order to use in decryption process
    
    unsigned char iv [AES_BLOCK_SIZE];
    if((numOfBytes = read(client_socket, iv , AES_BLOCK_SIZE))<0)
    {
            printf("Server: Error in receiving iv from client\n");
            close(client_socket);
            close(server_socket);
            free(sockets);
            printf("pbproxy_s ---> sshd thread is finished\n");
            return NULL;
    }
    if(numOfBytes != 16)
    {
        printf("Server: received iv length should be 16 bytes");
        close(client_socket);
        close(server_socket);
       	free(sockets);
        printf("pbproxy_s ---> sshd thread is finished\n");
        return NULL;   
    }    
    
    
    //Initiate decryption state
    
    struct ctr_state dec_state;
    init_ctr(&dec_state, iv);
    
    
    
     while(1)
    {
        //Receive packets from pbproxy_c
        if((numOfBytes = read(client_socket, inBuf, bufSize)) <0)
        {
            printf("Server: Error in receiving data from pbproxy client");
            close(client_socket);
            close(server_socket);
            free(sockets);
            printf("pbproxy_s ---> sshd thread is finished\n");
            return NULL;   
        }
        //If the following condition is satisfied, it means pbproxy_c connection is closed
        if(numOfBytes == 0)
        {
            printf("Server: The client connection is closed\n");
            close(client_socket);
	    close(server_socket);
            free(sockets);
            printf("pbproxy_s ---> sshd thread is finished\n");
            return NULL;            
        }
        if(numOfBytes > 0)
        {
           
            //Decrypt the data
            numOfBytes = decrypt(keyFile, iv, &dec_state, inBuf, numOfBytes, plainText);
            
            
            if(numOfBytes < 0)
            {
                printf("Server: decryption error");
                close(client_socket);
                close(server_socket);
                free(sockets);
                printf("Decryption Error: pbproxy_s ---> sshd thread is finished\n");
                return NULL;   
            }    
            
            //Send data to sshd
            if((numOfBytes = sendData(server_socket, plainText, numOfBytes))<0)
            {
                printf("Server: Error in sending data to ssh server");
                close(client_socket);
                close(server_socket);
                free(sockets);
                printf("pbproxy_s ---> sshd thread is finished\n");
                return NULL;   
            }
            if(numOfBytes == 0)
            {
                printf("Server: The pbproxy_s --->sshd connection is closed\n");
		close(server_socket);                
		close(client_socket);
                free(sockets);
                printf("pbproxy_s ---> sshd thread is finished\n");
                return NULL;  
            }
            //printf("%d bytes sent to server \n", numOfBytes );
        }
         
    }    
    return 0;
}

//This function return IP address for a given host name!
//It return the input as the output if the input is a valid IP address by itself
int HostNameToIP(char *hostname , char *ip)
{
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
		
	if ( (he = gethostbyname( hostname ) ) == NULL) 
	{	
		return 0;
	}
	
	addr_list = (struct in_addr **) he->h_addr_list;
	
	for(i = 0; addr_list[i] != NULL; i++) 
	{
		//Return the first one;
		strcpy(ip , inet_ntoa(*addr_list[i]) );
	}
	
	return 1;
}

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{
   
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    
    //In this mode of encryption we only need 8 bytes of IV!
    memset(state->ivec + 8, 0, 8);
 
    memcpy(state->ivec, iv, 8);
    
    return 1; 
}


 
//This the encryption function!
//It uses  AES_ctr128_encrypt to encrypt the data

int encrypt(char * keyfile, unsigned char * iv, struct ctr_state * enc_state, char * inbuffer, int inBufSize , char * outbuffer)
{
    unsigned char plaintext[AES_BLOCK_SIZE];
    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char enc_key[16];
    AES_KEY key;
    int tmp;
    FILE * key_file;
    int len;
    int i;
    int outBufCounter;
    
    key_file = fopen(keyfile, "rb");
    
    if(key_file == NULL)
    {
        return -1;
    }
    
    tmp = fread(enc_key, 1, AES_BLOCK_SIZE, key_file);    
    if(tmp != 16)
    {
        return -1;
    }
    fclose(key_file);
    
     //Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        return -1;
    }
    
    outBufCounter= 0;
    len = 0;
    
    //Encrypting the data block by block
    while(len<inBufSize)
    {
        tmp = 0;
        for(i =len; i < (len + AES_BLOCK_SIZE) && i < inBufSize; i++)
        {
            plaintext[i-len] = inbuffer[i];
            tmp++;
        }
        AES_ctr128_encrypt(plaintext, ciphertext, tmp, &key, enc_state->ivec, enc_state->ecount, &(enc_state->num));
        for(i = 0; i < tmp ; i++ )
        {
            outbuffer[outBufCounter + i] = ciphertext[i];
        }
        
        outBufCounter +=  tmp ;
        len += AES_BLOCK_SIZE;
    }       
    return outBufCounter ; 

}
 

int decrypt(char * keyfile, unsigned char * iv, struct ctr_state * dec_state, char * inbuffer, int inBufSize , char * outbuffer)
{
  
    unsigned char plaintext[AES_BLOCK_SIZE];
    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char enc_key[16];
    AES_KEY key;
    int tmp;
    FILE * key_file ;
    int len;
    int i;
    int outBufCounter;
 
    key_file = fopen(keyfile, "rb");
    
    if(key_file == NULL)
    {
        return -1;
    }
    
    tmp = fread(enc_key, 1, AES_BLOCK_SIZE, key_file);    
    if(tmp != 16)
    {
        return -1;
    }
    fclose(key_file);
    
     //Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        return -1;
    }
    

    len = 0;
    outBufCounter=0;

    //Decrypting block by block
    //Notice the encryption and decryption function are same
    while(len<inBufSize)
    {
        tmp = 0;
        for(i =len; i < (len + AES_BLOCK_SIZE) && i < inBufSize; i++)
        {
            ciphertext[i-len] = inbuffer[i];
            tmp++;
        }
        
        AES_ctr128_encrypt(ciphertext, plaintext, tmp, &key, dec_state->ivec, dec_state->ecount, &(dec_state->num));
       
        for(i = 0; i < tmp ; i++ )
        {
            outbuffer[outBufCounter + i] = plaintext[i];
        }
        
        outBufCounter +=  tmp ;
                
        len += AES_BLOCK_SIZE;
    }
    
    return outBufCounter ;
    
}
 


//The following functions are used to log error messages in the specified files
void log (const char * message)
{
        static bool logCreated = false;
        
        FILE *file;
        
	if (!logCreated) {
		file = fopen(LOGFILE, "w");
		logCreated = true;
	}
	else		
		file = fopen(LOGFILE, "a");
		
	if (file == NULL) {
		if (logCreated)
			logCreated = false;
		return;
	}
	else
	{
		fputs(message, file);
		fclose(file);
	}
 
	if (file)
		fclose(file);
}
 
void logError (const char *message)
{
	log(message);
	log("\n");
	
}
