// IMPORTAN !!!
// This was a temorary attempt before the MTD64 was created. 
// I used this program to introduce the socket handling and other important function in my thesis
// This simple server program will responds to queries with the IPv4 address "100.101.102.103" and 
// with the IPv6 address "2001:db8:face:b00c:beef:0:acdc:edda" in case of it receives "A" or "AAAA" query 
#include <iostream>
#include <sstream>
#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h> 
#include <string.h>

#define BUFLEN 512

/* Error handling */
void err(const char str[]) {
	perror(str);
	exit(1);
	}


/* Determining the string (domain name) length which is starting at the given char array */
int string_length(unsigned char *data) {
	
	int length=0;
	unsigned char chk=data[0];
	
	while(chk != 0x00) {
		length=length+chk+1;
		chk=data[length];
		}
	return length;
}

/* Fill in the given hex values into the given array */
int fill(unsigned char *answ, unsigned long long tmp, int size) {
	int i;
	for (i=0; i < size; i++) {
		answ[i] = (tmp >> (size-i-1)*8) & 0xff;
	}
	return size;
}

/* Thread for the complete handling of a request */
void send_response(char *dest_ip, int dest_port, unsigned char msg[BUFLEN], int sockfd, int recvlen) {
	
	struct sockaddr_in dest_addr;
	int i,j;
	unsigned char *answ;
	int slen; // String length
	int next; // For indexins answ

	answ= (unsigned char*)malloc(150*sizeof(unsigned char));

	/* Filling the answer packet */
	memcpy(answ,msg,2); // Copy Transaction ID to response message from query message
	answ[2]=0x81; // Sets the value of flags in the headerlags block Standardy query response, No error
	answ[3]=0x80; // 0x8180
	next=4;
	
	// Check whether the type of the DNS query it "A"
 	if (msg[recvlen-4]==0x00 && msg[recvlen-3]==0x01) {
		
		printf("\n--> \"A\" record type");
		// Questions (2 byte), Answer RRs (2 byte), Authority RRs (2 byte), Additional RRs (2 byte)
		next+=fill(answ+next, 0x0001000100010000, 8);

		// _Queries block_ copied from the query message
		slen=string_length(msg+next); 	// Determine the string length of the domain name
		memcpy(answ+next, msg+12, slen);// Domain name starts at byte number 12
		next+=slen+1;
	
		// _Queries block_: type (2 byte), class (2 byte) | _Answers block_: name (2 byte), type (2 byte)
		next+=fill(answ+next, 0x00010001c00c0001, 8);
		// _Answers block_: class (2 byte), TTL (4 byte), data length (2 byte)
		next+=fill(answ+next, 0x0001000000810004, 8);
		// _Answer block_: Addr (4 byte) -> IP Address: 100.101.102.103 in hex format
		next+=fill(answ+next, 0x64656667, 4);


        	// _Authoritative nameservers block_: name (2 byte), type (2 byte), class (2 byte), TTL (2 byte...)
	        next+=fill(answ+next, 0xc00c000200010000, 8);
		// _Authoritative nameservers block_: TTL (... 2 byte), data length (2 byte), Name server (4 byte...)
		next+=fill(answ+next, 0x000200040161c00c, 8);
	
		}

        // Check whether the type of the DNS query it "AAAA" 
	else if (msg[recvlen-4]==0x00 && msg[recvlen-3]==0x1c) {	
		
		printf("\n--> \"AAAA\" record type");
		// Questions (2 byte), Answer RRs (2 byte), Authority RRs (2 byte), Additional RRs (2 byte)
		next+=fill(answ+next, 0x0001000100000000, 8);

		// _Queries block_ copied from the query message
	        slen=string_length(msg+next); 	// Determine the string length of the domain name
	        memcpy(answ+next, msg+12, slen);// Domain name starts at byte number 12
	        next+=slen+1;

		// _Queries block_: type (2 byte), class (2 byte) | _Answers block_: name (2 byte), type (2 byte)
                next+=fill(answ+next, 0x001c0001c00c001c, 8);
		// _Answers block_: class (2 byte), TTL (4 byte), data length (2 byte)
                next+=fill(answ+next, 0x0001000000050010, 8);
		
		// 2001:db8:face:b00c:beef::acdc:edda
		// _Answer block_: Addr (4 byte) -> IP Address: 100.101.102.103 in hex format	
		next+=fill(answ+next, 0x20010db8faceb00c, 8);
		next+=fill(answ+next, 0xbeef0000acdcedda, 8);

		}


	// If the type of the query is not 'A' nor 'AAAA' then send back the answer: No such record
	else {
		
		printf("\n--> Unrecognised record type");
		// Questions (1), Answer RRs (0), Authority RRs (1), Additional RRs (0)
		next+=fill(answ+next, 0x0001000000010000, 8);
	
		// _Queries block_ copied from the query message
		slen=string_length(msg+next); 	// Determine the string length of the domain name
	        memcpy(answ+next, msg+12, slen);// Domain name starts at byte number 12
	        next+=slen+1;

		// Query type copied from the query message
		answ[next++]=msg[12+slen+1];
		answ[next++]=msg[12+slen+2];

		// _Queries block_: class (2 byte) | _Answers block_: name (2 byte), type (2 byte)
	        next+=fill(answ+next, 0x0001, 2);

		// _Authoritative nameservers_: name (2 byte), type (2 byte), class (2 byte), TTL (2 byte...)
	        next+=fill(answ+next, 0xc00c000200010000, 8);
	        // _Authoritative nameservers_: TTL (... 2 byte), data length (2 byte), Name server (4 byte...)
	        next+=fill(answ+next, 0x000200040161c00c, 8);

	        // _Additional records block_: name (2 byte), type (2 byte), class (2 byte), TTL (2 byte...)
	        next+=fill(answ+next, 0xc03a000100010000, 8);
		// _Additional records block_: TTL (...2 byte), data length (2 byte), IP address (4 byte)
	        next+=fill(answ+next, 0x87f60004c33841ac, 8);

		}

	dest_addr.sin_family = AF_INET;
	inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr.s_addr);
	dest_addr.sin_port = htons(dest_port);
	
	std::cout << "\nSending the following packet to: " << dest_ip << ":" << dest_port << " \n\n";

	// Printing the packet data in similirat format which Wireshark uses
	j=10;
	for(i=0; i<next; i++) { 
		printf("|%02x", (answ[i])) ;
		j++;
		if(j%16==0 && i+1!=next) std::cout << "|\n";
		else if (j%8==0 && i+1!=next) std:: cout << "|  ";
		 }

	printf("|\n----------------------------------------------------\n");
	if ( sendto(sockfd, answ, next, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) err("sendto");

	}


int main(void) {

	int sockfd;   // Socket file descriptor
	int recvlen;  // Legth of the received packet  
	struct sockaddr_in my_addr;	// Own address
	struct sockaddr_in cli_addr;	// Client address
	socklen_t slen=sizeof(cli_addr);// Legth of address
	unsigned char buf[BUFLEN]; 	// Packet data container
	char dest_ip[15];

	/* Create a UDP socket */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1) err("socket");
	else printf("Server : Socket() successful\n");

	/* Socket settings */
	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = AF_INET; // Address family
	my_addr.sin_port = htons(53); // UDP port number
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY); // To any valid IP address

	/* Bind the socket */
	if (bind(sockfd, (struct sockaddr* ) &my_addr, sizeof(my_addr))==-1) err("bind");
	else printf("Server : bind() successful\n\n");

	/* Loop for receiving UDP packets */
	while(1) {

		if ( (recvlen = recvfrom(sockfd, buf, BUFLEN, 0, (struct sockaddr*)&cli_addr, &slen)) <= 0) err("recvfrom()");
		
		printf("\nReceived packet from %s:%d length: %d", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), recvlen);
		
		strcpy(dest_ip, inet_ntoa(cli_addr.sin_addr));

		std::thread t(send_response, dest_ip, ntohs(cli_addr.sin_port), buf, sockfd, recvlen);
		t.detach();
		
		}

	close(sockfd);
	return 0;
	}
