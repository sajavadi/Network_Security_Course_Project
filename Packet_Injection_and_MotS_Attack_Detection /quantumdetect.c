/* 
 * File:   quantumdetect.c
 * Author: Seyyedahmad Javadi
 *
 * Created on May 3, 2015, 11:20 PM
 */

//In order to this program to be compiled and executed successfully, we need to install pcre library
//We use this powerful library for providing pattern matching capability


#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

//This is the maximum lenght of our history
//We keep this number of http response in the memory to compare the future packet with them

#define MaxHistoryLength 500

//These are peace of information we keep for each packet
struct packetInfo 
{
    long int capture_time_sec;       /*date and time in second*/  
    long int capture_time_usec;      /*Millisecond section of time*/
    struct in_addr ip_src,ip_dst;    /*Source and destination IP address*/
    unsigned short  th_sport;        /* source port */
    unsigned short  th_dport;        /* destination port */
    //uint32_t th_seq;                 /* sequence number */
    //uint32_t th_ack;                 /* acknowledgment number */
    int  th_seq;
    int  th_ack; 
    char * payload;                  /*packet payload*/
    int payloadSize;
};

//This is the function that is called in function online_pcap! 
void packet_analyzer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

//This function is called when we want to listen to a interface! 
void online_detect(char *interface, char* filter);

//This function is called when we want to read from a pcap file!

void offline_detect(char *file, char* filter);

//I used the existing source code in the web for the following two functions!
void print_hex_ascii_line(const char *payload, int len, int offset);
void print_payload(const char *payload, int len);


//Since wee need to access to history of http response packet, I defined them ad global variables

struct packetInfo * history[MaxHistoryLength];
int historySize=0;
int historyIndex=0;
int history_is_full=0;
int num_of_spoofed_packets=0;

int main (int argc, char **argv)
{
  
  // A set of variables that store the user input parameters for the program! 
 
  int iflag = 0;
  int rflag = 0;


  char *interface = NULL;
  char *file = NULL;
  char *expression = NULL;

  int c;	
  // Here I use getopt function to read the program input options!
  while ((c = getopt (argc, argv, "i:r:")) != -1)
    switch (c)
      {
      case 'i':
        iflag = 1;
	interface =  optarg;
        break;
      case 'r':
        rflag = 1;
	file =  optarg;
	break;
      default:
	printf("Error!!! Unknown Parameters!!!\n");
        abort ();
      }

  if (argv[optind] != NULL)
	expression = argv[optind];

  
  printf ("iflag = %d, interface = %s, rflag = %d, file = %s\n",
          iflag, interface, rflag, file);
  printf ("expression = %s\n", expression);

  // I call online_pcap if no pcap file is specified. 
  // Otherwise, if rflag is specified, I call offline_pcap
  // If both iflag and rflag are specified, error message is printed and the program aborted! 
  
  if(rflag == 1 && iflag == 1)
  {
      printf("You can not use both i and -r flags\n");
      return 0;
  }   
  
  if (rflag == 0)
  {

	online_detect(interface, expression); 
  }
  else 
  { 
	offline_detect(file, expression);
  }

  return 0;
}


//This function prints the detailed information of the actual and spoofed packet

void print_attack_info(struct pcap_pkthdr header,struct ip * ip_header, struct tcphdr * tcp_header, 
        char * payload, int payload_size, struct packetInfo * history[], int history_index)
{
    
    int pSize;
    if( history[history_index]->payloadSize <= payload_size)
    {
        pSize = history[history_index]->payloadSize ;
    }
    else
    {
        pSize = payload_size;
    }
    
    
    printf("\n*********** %dth attack is detected *************\n\n", num_of_spoofed_packets);
    printf("First packet :\n");
    printf("Capture Time: ");
    printf("%s ",ctime((const time_t *) &(history[history_index]->capture_time_sec)));
    printf("Milliseconds: %ld \n", history[history_index]->capture_time_usec);
    printf("%s:%d --> ", inet_ntoa(history[history_index]->ip_src), history[history_index]->th_sport);
    printf("%s:%d \n", inet_ntoa(history[history_index]->ip_dst), history[history_index]->th_dport);
    printf("Seq Num:%d  ; Ack Num: %d\n", history[history_index]->th_seq, history[history_index]->th_ack );
    printf("Payload (We print just the  minimum length of two packets! They can be longer!): \n");
    print_payload(history[history_index]->payload, pSize);
           
    //Second packet
    
    printf("\nSecond packet:\n\n");
    printf("Capture Time: ");
    printf("%s ",ctime((const time_t *) &header.ts.tv_sec));
    printf("Milliseconds: %d \n", header.ts.tv_usec); 
    
    printf("%s:%d --> ", inet_ntoa(ip_header->ip_src), tcp_header->th_sport);
    printf("%s:%d \n", inet_ntoa(ip_header->ip_dst), tcp_header->th_dport);
    
    printf("Seq Num:%d  ; Ack Num: %d\n", tcp_header->th_seq, tcp_header->th_ack);
    
    
    printf("Payload (We print just the  minimum length of two packets! They can be longer!): \n");    
    print_payload(payload, pSize);
    
}



//This packet check weather the given http response can be considered as an part of attack
//It returns the index of the packet in the history array that matches to given packet in success
//This is the case if the packets headers are equal but the packet size or the packet payload is different
//It returns -2 if this is a new packet
//It returns -1 if this a retransmission
//This is the case if both packets are exactly similar


int check_repetitive_respone(struct packetInfo * history[], int hSize, struct ip * ip_header, struct tcphdr * tcp_header, 
        char * payload, int payload_size)
{
    int i,j,sw=0;
    
    for( i = 0 ; i < hSize; i++)
    {
        if (history[i]->ip_src.s_addr != ip_header->ip_src.s_addr)
            continue;
        if (history[i]->ip_dst.s_addr != ip_header->ip_dst.s_addr)
            continue;
        if (history[i]->th_sport != tcp_header->th_sport)
            continue;
        if (history[i]->th_dport != tcp_header->th_dport)
            continue;
        if (history[i]->th_seq != tcp_header->th_seq)
            continue;
        if (history[i]->th_ack != tcp_header->th_ack)
            continue;
        if (history[i]->payloadSize != payload_size)
            //This is an attack detection
            return i;
        sw = 1;
        for(j = 0; j < payload_size; j++)
        {
            if (history[i]->payload[j] != payload[j])
               //This is an attack detection
                return i; 
        }
        
    }
    
    if (sw == 1)
    {
        //this is TCP retransmissions
        return -1;
    }      
    else 
    {    
        //this is new packet
        return -2;
    }    
}


//This function is responsible for parsing a packet in online_detect and use the previous function to detect  attack
//A pointer to this function is passed to pcap_loop function!!

void packet_analyzer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  char *payload;
  int payload_size;
  struct ip *ip_header;
  struct tcphdr *tcp_header;
                    
  bpf_u_int32 net;   
  int ethernet_offset = 14;
  u_char * packet_ptr; 
  int ip_header_size ;
  int tcp_header_size;
  int packet_length;
  int src_port;
  int dst_port;
  char protocol[20]="";
  int tmp;
  
  //Regular expression for detecting HTTP response
  
  
  /*As far as the strcuture of tcp header is considered,
    mask is used to read the data offset field in the TCP header correctly!!
    Here is the related section in TCP header structure definition:
    
    #if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	th_x2:4,	 (unused) 
		th_off:4;        data offset 
    #endif
    #if BYTE_ORDER == BIG_ENDIAN 
	u_char	th_off:4,	
		th_x2:4;		 (unused) 
 */

  char mask;
  if(BYTE_ORDER == LITTLE_ENDIAN ) //most of the time 
	mask = 0x0f;
  else
	mask = 0xf0;
  packet_ptr = (u_char *)packet; 
  packet_ptr += ethernet_offset; 
  ip_header = (struct ip *)packet_ptr;
  packet_length = ntohs(ip_header->ip_len);
  ip_header_size = (ip_header->ip_hl & mask)*4;
 
  /* Jump to the begging of the transport layer protocol! 
   filed ip_p in the ip header specifies the upper layer protocol!
   According the following website, the protocol number for TCP
   is 6!!
   http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
  */
  packet_ptr += ip_header_size;
  
  if(ip_header->ip_p == 6) {
        strcpy(protocol, "TCP");
        tcp_header = (struct tcphdr *) (packet_ptr);
        src_port =  ntohs(tcp_header->th_sport);
        dst_port=  ntohs(tcp_header->th_dport);
        tcp_header_size= (int) (tcp_header->th_off & mask) *4; 
        payload = (char *)(packet_ptr + tcp_header_size);
        payload_size = packet_length - (ip_header_size + tcp_header_size);
        
        if(payload_size>0){  
            //Checking whether this is a part of attack or not
            tmp = check_repetitive_respone(history, historySize, ip_header, tcp_header, payload, payload_size);
            if (tmp >= 0 )
            {
                num_of_spoofed_packets++;
                print_attack_info(*header, ip_header, tcp_header, payload, payload_size, history, tmp);
            }    
            else if (tmp == -2)
            {
                //This is a new seen packet! Add it to history!!
                
                history[historyIndex]= malloc (sizeof (struct packetInfo));
                history[historyIndex]->capture_time_sec = header->ts.tv_sec;
                history[historyIndex]->capture_time_usec = header->ts.tv_usec;
                history[historyIndex]->ip_dst = ip_header->ip_dst;
                history[historyIndex]->ip_src = ip_header->ip_src;
                history[historyIndex]->th_ack = tcp_header->th_ack;
                history[historyIndex]->th_seq = tcp_header->th_seq;
                history[historyIndex]->th_dport = tcp_header->th_dport;
                history[historyIndex]->th_sport = tcp_header->th_sport;
                history[historyIndex]->payload = malloc(payload_size);
                memcpy(history[historyIndex]->payload, payload, payload_size);
                history[historyIndex]->payloadSize = payload_size;
                
                //We have limited history buffer!!!
                
                if(historyIndex < MaxHistoryLength -1)
                {
                    historyIndex++;
                    if(history_is_full == 0)
                    {
                        historySize++;
                    }
                }
                else
                {
                    historyIndex = 0;
                    history_is_full = 1;
                }
            }
        }
    }
}


//This function setups required actions to listen to the interface and call packet_analyzer per packet

void online_detect(char *interface, char* filter)
{
 
  char errorbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  struct bpf_program fp; // hold compiled filter
  bpf_u_int32 netmask; //netmask of the device
  bpf_u_int32 ip; //ip of the device 

  if(interface == NULL)
  {
	//slecet a device to listen into
	interface = pcap_lookupdev(errorbuf);
	if (interface == NULL) {
		printf("Default device is not found\n");
                return;
        }
  }
  
  //Ask pcap for the network address and mask of the device	
  if (pcap_lookupnet(interface, &ip, &netmask, errorbuf) == -1) {
	printf("Netmask error for device %s \n",interface);
	return;
  }
  //Opening the device in promiscuous mode!!
  handle = pcap_open_live(interface, BUFSIZ , 1 , 1, errorbuf);
  if (handle == NULL) {
	printf("Error in opening device %s\n", interface);
	return;
  }
  if(filter != NULL)
  {
        //compile the input filter if it is not null
	if (pcap_compile(handle, &fp, filter, 0, ip) == -1)
        {
                printf("Parse  error for the filter: %s\n", filter);
        }
	// Set the compiled filter
        if (pcap_setfilter(handle, &fp) == -1) {
                printf("Setting error for the filter: %s\n", filter );
        }
  }
  
  pcap_loop(handle, -1 , packet_analyzer, NULL);
  pcap_freecode(&fp);
  pcap_close(handle);
  
}



//This function does the same thing for the pcap file
void offline_detect(char *file, char* filter)
{
  struct pcap_pkthdr header;
  char *packet; 
  char *payload;
  int payload_size;
  pcap_t *handle;
  char errorbuf[PCAP_ERRBUF_SIZE];
  struct ip *ip_header;
  struct tcphdr *tcp_header;
  struct bpf_program fp;                      
  int ip_header_size ;
  int tcp_header_size;
  int packet_length;
  int src_port;
  int dst_port;
  char protocol[20]="";
  int tmp;
  
  
  
  handle = pcap_open_offline(file, errorbuf);  
  if (handle == NULL) 
  {
      printf("Error in the opening of the pcap file %s \n", file);
      return;
  }
 
  if(filter != NULL)
  {
	if (pcap_compile(handle, &fp, filter, 0, 0) == -1)
  	{
		printf("Error in the parsing the filter:  %s\n", filter);
  	}

  	if (pcap_setfilter(handle, &fp) == -1) {
        	printf("Error in the setting the filter:  %s\n", filter );
 	}
  }
 
  char mask;
  if(BYTE_ORDER == LITTLE_ENDIAN ) //most of the time 
	mask = 0x0f;
  else
	mask = 0xf0;
  while ((packet = pcap_next(handle,&header)) != NULL) {

     	char *packet_ptr = (char *)packet; 
      	packet_ptr += sizeof(struct ether_header);
      	ip_header = (struct ip *)packet_ptr;
	packet_length = ntohs(ip_header->ip_len);
	ip_header_size = (ip_header->ip_hl & mask)*4;
	packet_ptr += ip_header_size;
        
	if(ip_header->ip_p == 6){		
            strcpy(protocol, "TCP");
            tcp_header = (struct tcphdr *) (packet_ptr);
            src_port =  ntohs(tcp_header->th_sport);
            dst_port=  ntohs(tcp_header->th_dport);
            tcp_header_size= (int) (tcp_header->th_off & mask) *4; 
            payload = (char *)(packet_ptr + tcp_header_size);
            payload_size = packet_length - (ip_header_size + tcp_header_size);
            
            if(payload_size > 0) {
                tmp = check_repetitive_respone(history, historySize, ip_header, tcp_header, payload, payload_size);
                if (tmp >= 0 )
                {
                    num_of_spoofed_packets++;
                    print_attack_info(header, ip_header, tcp_header, payload, payload_size, history, tmp);
                }    
                else if (tmp == -2)
                {
                    history[historyIndex]= malloc (sizeof (struct packetInfo));
                    history[historyIndex]->capture_time_sec = header.ts.tv_sec;
                    history[historyIndex]->capture_time_usec = header.ts.tv_usec;
                    history[historyIndex]->ip_dst = ip_header->ip_dst;
                    history[historyIndex]->ip_src = ip_header->ip_src;
                    history[historyIndex]->th_ack = tcp_header->th_ack;
                    history[historyIndex]->th_seq = tcp_header->th_seq;
                    history[historyIndex]->th_dport = tcp_header->th_dport;
                    history[historyIndex]->th_sport = tcp_header->th_sport;
                    history[historyIndex]->payload = malloc(payload_size);
                    memcpy(history[historyIndex]->payload, payload, payload_size);
                    history[historyIndex]->payloadSize = payload_size;
                    
                    if(historyIndex < MaxHistoryLength - 1)
                    {
                        historyIndex++;
                        if(history_is_full == 0)
                        {
                            historySize++;
                        }
                    }
                        
                    else
                    {
                        historyIndex = 0;
                        history_is_full = 1;
                    }
                }
            }
            
        }
   }
  pcap_close(handle); 
}


void
print_hex_ascii_line(const char *payload, int len, int offset)
{

	int i;
	int gap;
	const char *ch;


	printf("%05d   ", offset);
	
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		if (i == 7)
			printf(" ");
	}
	if (len < 8)
		printf(" ");
	
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	

	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void
print_payload(const char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;		
	int line_len;
	int offset = 0;					
	const char *ch = payload;

	if (len <= 0)
		return;

	
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	for ( ;; ) {
		line_len = line_width % len_rem;
		print_hex_ascii_line(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width) {
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}




