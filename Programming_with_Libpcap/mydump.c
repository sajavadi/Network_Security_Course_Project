//Seyyed Ahmad Javadi

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

//This is the function that is called in function online_pcap! 
//It parses the packet and print the required outputs!
void packet_analyzer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

//This function is called when we want to listen to a interface! 
void online_pcap(char *interface, char* filter);

//This function is called when we want to read from a pcap file!

void offline_pcap(char *file, char* filter, char * str, int gflag);

//I used the existing source code in the web for the followin two functins!
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);

// These are two global variables that shows the input string and g flag for the program!
// Since, I need to use these two variables in the packet_analyzer, I defined them as global! 
char *search_key = NULL;
int gflag = 0; 


int main (int argc, char **argv)
{
  
  // A set of variables that stor the usr input parameters for the program! 
 
  int iflag = 0;
  int rflag = 0;
  int sflag = 0;

  char *interface = NULL;
  char *file = NULL;
  char *expression = NULL;

  int c;	
  // Here I use getopt function to read the program input options!
  while ((c = getopt (argc, argv, "i:r:s:g")) != -1)
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
      case 's':
        sflag = 1;
	search_key =  optarg;
        break;
      case 'g':
       	gflag = 1;
	break;
      default:
	printf("Error!!! Unknown Parameters!!!\n");
        abort ();
      }

  if (argv[optind] != NULL)
	expression = argv[optind];

  
  // printf ("iflag = %d, interface = %s, rflag = %d, file = %s\n",
  //        iflag, interface, rflag, file);
  //  printf ("sflag = %d,string = %s, gflag = %d, expression = %s\n",
  //        sflag, search_key, gflag, expression);

  // I call online_pcap if no pcap file is specified. 
  // Otherwise, if rflag is specified, I call offline_pcap
  // If both iflag and rflag are specified, error message is printed and the program aborted! 
  if (rflag == 0)
  {

	online_pcap(interface, expression); 
  }
  else if(rflag == 1 && iflag == 0 )
  { 
	offline_pcap(file, expression, search_key, gflag);
  }
  else
  {
  	printf("Error!!!! Please use one of the parameters i and r \n");
	abort();
  }
  

  return 0;
}


/*This functions simply searchs the target string in the str
 and returns the location of the first match!
*/	
int StrStr(const char *str, const char *target, int str_size) {
  if (!*target) 
	return -1;
  char *p1 = (char*)str;
  int i=0;
  char *p1Begin;
  char *p2;
  while(i < str_size){
	p1Begin = p1;
	p2 = (char*)target;
  	while (*p1 && *p2 && *p1 == *p2) {
		p1++;
      		p2++;
    	}
    	if (!*p2)
		return i;
	p1 = p1Begin + 1;
    	i++;	
  }
  return -1;
}

//This function is responsible for parsing a packet and printing the reqired outputs!
//A pointer to this function is passed to pcap_loop function!!

void packet_analyzer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const char *payload;
  int payload_size;
  struct ip *ip_header;
  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
  struct icmphdr *icmp_header;                     
  bpf_u_int32 net;   
  int ethernet_offset = 14;
  u_char * packet_ptr; 
  int ip_header_size ;
  int tcp_header_size;
  int udp_header_size = sizeof (struct udphdr);
  int icmp_header_size = sizeof (struct icmphdr);
  int packet_length;
  int src_port;
  int dst_port;
  char protocol[20]="";
  int i;
  char *char_ptr; 
  const u_char *tmp;
  char buf[25];
  
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
   According the following website, the protocol number for TCP, UDP, and ICMP
   is 6, 17, 1 !!
   http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
  */
  packet_ptr += ip_header_size;
  switch(ip_header->ip_p) {
     	case 6:  //TCP
       	        strcpy(protocol, "TCP");
		tcp_header = (struct tcphdr *) (packet_ptr);
   		src_port =  ntohs(tcp_header->th_sport);
		dst_port=  ntohs(tcp_header->th_dport);	
		tcp_header_size= (int) (tcp_header->th_off & mask) *4; 
		payload = (u_char *)(packet_ptr+ tcp_header_size);
        	payload_size = packet_length - (ip_header_size + tcp_header_size);
		break;
        case 17: //UDP
           	strcpy(protocol, "UDP");
		udp_header = (struct udphdr *) (packet_ptr);
		src_port =  ntohs(udp_header->uh_sport);
		dst_port =  ntohs(udp_header->uh_dport);
		payload = (u_char *)(packet_ptr+ udp_header_size);
		payload_size = packet_length - (ip_header_size + udp_header_size);
            	break;
       	case 1: //ICMP
		strcpy(protocol, "ICMP");
		src_port = -1;
		dst_port = -1;
		payload = (u_char *)(packet_ptr+ icmp_header_size);
                payload_size = packet_length - (ip_header_size + icmp_header_size);
		break; 
   	default:
		payload_size = -1;
		strcpy(protocol, "OTHER");
		src_port = -1;
		dst_port = -1;
  }	
  
  if(search_key != NULL)
  {
	if(payload_size <= 0) //this also includes packets whose protocol are OTHER
		return;
	
	if(StrStr(payload, search_key, payload_size) == -1)
	{
		return;
	}
  }


  //print current time!
       
  time_t now;
  time(&now);
  strcpy(buf, ctime(&now));
  buf[24]='\0';
  printf("%s ",buf);


  printf("%s ", protocol);
  if(src_port != -1)
       	printf("%s:%d ", inet_ntoa(ip_header-> ip_src), src_port);
  else
        printf("%s ", inet_ntoa(ip_header-> ip_src));
  printf("-> ");
  if(dst_port != -1)
       printf("%s:%d ", inet_ntoa(ip_header-> ip_dst), dst_port);
  else
       printf("%s ", inet_ntoa(ip_header-> ip_dst));
  printf("len %d\n", packet_length);
    	
  if(gflag == 1 && payload_size > 0)
  {
	// The first line in http header is as follows:
	// Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
	// SP character hex = 0x20
	i = 0;
	tmp =payload;
	while(*tmp != 0x20) 
	{
		printf("%c",*tmp);
		tmp++;
		i++;
	}	
	tmp++;		
	printf(" ");	
	while(*tmp != 0x20)
        {
                printf("%c",*tmp);
                tmp++;
		i++;
		if(i % 77 == 0 )
			printf("\n");
        }
	printf("\n");
  }
  else if (payload_size > 0) 
  {
        print_payload(payload, payload_size);
  }
       
  printf("\n");  
}
void online_pcap(char *interface, char* filter)
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
  handle = pcap_open_live(interface, BUFSIZ , 1 , -1, errorbuf);
  if (handle == NULL) {
	printf("Error in opening device %s\n", interface);
	return;
  }
  if(gflag == 0 && filter != NULL)
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
  else if (gflag == 1)
  {
     // We use the following filter for http get and post request
     // The idea is very simple. 
     // In fact it first read the payload offset from the tcp packet header (4 bit long of 8 bits 
     // starting from byte 12).
     // Then shift the offset two times to the right to calculate the index of first byte of the payload
     // Then read the first 4 bytes of the payload!!
     // Considering theis fact the GET request starts with "GET " and post request starts with "POST"
     // It simply compares the first 4 bytes of the payload to determine whether this is the 
     // get or post request!!! 
     char http_filter[] = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or (tcp dst port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)";

	if (pcap_compile(handle, &fp, http_filter, 0, ip) == -1)
        {
                printf("Parse error for the http request filter \n" );
        }

        if (pcap_setfilter(handle, &fp) == -1) {
                printf("Setting error for http request filter\n");
        }

  }
  pcap_loop(handle, -1 , packet_analyzer, NULL);
  pcap_freecode(&fp);
  pcap_close(handle);

  
}



//This function does the same thing for the pcap file

void offline_pcap(char *file, char* filter, char * str, int gflag)
{
  struct pcap_pkthdr header;
  const u_char *packet; 
  const char *payload;
  int payload_size;
  pcap_t *handle;
  char errorbuf[PCAP_ERRBUF_SIZE];
  struct ip *ip_header;
  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
  struct icmphdr *icmp_header;
  struct bpf_program fp;                      
  int ethernet_type;
  int ethernet_offset = 14;
  u_char * packet_ptr; 
  int ip_header_size ;
  int tcp_header_size;
  int udp_header_size = sizeof (struct udphdr);
  int icmp_header_size = sizeof (struct icmphdr);
  int packet_length;
  int src_port;
  int dst_port;
  char protocol[20]="";
  int i;
  char *char_ptr; 
  const u_char *tmp;
  char buf[25];
  handle = pcap_open_offline(file, errorbuf);  
  if (handle == NULL) 
  {
      printf("Error in the opening of the pcap file %s \n", file);
      return;
  }
 
  if(gflag == 0 && filter != NULL)
  {
	if (pcap_compile(handle, &fp, filter, 0, 0) == -1)
  	{
		printf("Error in the parsing the filter:  %s\n", filter);
  	}

  	if (pcap_setfilter(handle, &fp) == -1) {
        	printf("Error in the setting the filter:  %s\n", filter );
 	}
  }
  else if (gflag ==1)
  { 
	//The detailed explanation of this filter mentioned above!!
	char http_filter[] = "(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420) or (tcp dst port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354))";
	
	if (pcap_compile(handle, &fp, http_filter, 0, 0) == -1)
        {
                printf("Couldn't parse http filter \n" );
        }

        if (pcap_setfilter(handle, &fp) == -1) {
                printf("Couldn't install http filter\n");
        }

  }	

  char mask;
  if(BYTE_ORDER == LITTLE_ENDIAN ) //most of the time 
	mask = 0x0f;
  else
	mask = 0xf0;
  while (packet = pcap_next(handle,&header)) {

     	u_char *packet_ptr = (u_char *)packet; 
      	packet_ptr += ethernet_offset; 
      	ip_header = (struct ip *)packet_ptr;
	packet_length = ntohs(ip_header->ip_len);
	ip_header_size = (ip_header->ip_hl & mask)*4;
	packet_ptr += ip_header_size;
	switch(ip_header->ip_p) {
      		case 6: //TCP
       		        strcpy(protocol, "TCP");
			tcp_header = (struct tcphdr *) (packet_ptr);
	   		src_port =  ntohs(tcp_header->th_sport);
			dst_port=  ntohs(tcp_header->th_dport);
			tcp_header_size= (int) (tcp_header->th_off & mask) *4; 
			payload = (u_char *)(packet_ptr+ tcp_header_size);
        		payload_size = packet_length - (ip_header_size + tcp_header_size);
			break;
        	case 17: //UDP
           		strcpy(protocol, "UDP");
			udp_header = (struct udphdr *) (packet_ptr);
			src_port =  ntohs(udp_header->uh_sport);
			dst_port =  ntohs(udp_header->uh_dport);
			payload = (u_char *)(packet_ptr+ udp_header_size);
			payload_size = packet_length - (ip_header_size + udp_header_size);
            		break;
       		case 1: //ICMP
			strcpy(protocol, "ICMP");
			src_port = -1;
			dst_port = -1;
			payload = (u_char *)(packet_ptr+ icmp_header_size);
                        payload_size = packet_length - (ip_header_size + icmp_header_size);
			break; 
   		default:
			payload_size = -1;
			strcpy(protocol, "OTHER");
			src_port = -1;
			dst_port = -1;
	}	

	if(str != NULL)
	{
		if(payload_size <= 0)
			continue;
		if(StrStr(payload, str, payload_size) == -1 || strcmp(protocol, "OTHER") == 0 )
		{
			continue;
		}
	}

	//Convert the time stamp to a printable format       
	strcpy(buf, ctime((const time_t *) &header.ts.tv_sec));
	buf[24]='\0';
	printf("%s ",buf);
	//Print the protocol
	printf("%s ", protocol);
	//Print Src ip and port! Dst ip and port!!
        if(src_port != -1)
        	printf("%s:%d ", inet_ntoa(ip_header-> ip_src), src_port);
        else
                printf("%s ", inet_ntoa(ip_header-> ip_src));
        printf("-> ");
        if(dst_port != -1)
                printf("%s:%d ", inet_ntoa(ip_header-> ip_dst), dst_port);
        else
                printf("%s ", inet_ntoa(ip_header-> ip_dst));
        printf("len %d\n", packet_length);
	if(gflag == 1 && payload_size>0)
	{
		// Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
		// SP character hex = 0x20
		i=0;
		tmp =payload;
		while(*tmp != 0x20) 
		{
			printf("%c",*tmp);
			tmp++;
			i++;
		}	
		tmp++;		
		printf(" ");	
		while(*tmp != 0x20)
                {
                       	printf("%c",*tmp);
        	        tmp++;
			i++;
                	if(i % 77 == 0 )
                        	printf("\n");
		}
			printf("\n");
	}
	else if (payload_size > 0) 
	{
                print_payload(payload, payload_size);
        }
        
	printf("\n");
  }
  pcap_close(handle); 

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

void
print_payload(const u_char *payload, int len)
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



