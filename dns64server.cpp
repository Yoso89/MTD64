/* This is the main cpp file for Multi-Threaded DNS64 */
#include "header.h"
#define min( a, b ) ( ((a) < (b)) ? (a) : (b) )
#define max( a, b ) ( ((a) > (b)) ? (a) : (b) )

/* Logging and error handling functions */

void loginfo(const char str[]) {
	syslog(LOG_INFO, "<info> %s", str);
	}


void logerror(const char str[]) {
	syslog(LOG_ERR, "<ERROR> %s", str);
	if (errno != 0) syslog(LOG_ERR, "<ERROR> Errno value: %s", strerror(errno));
	
	closelog();
	exit(1);
	}

void logerror(const char str[], int line) {
	syslog(LOG_ERR, "<ERROR> %s at line %d", str, line);
	if (errno != 0) syslog(LOG_ERR, "<ERROR> Errno value: %s", strerror(errno));
	
	closelog();
	exit(1);
	}


void logwarning(const char str[]) {
	syslog(LOG_WARNING, "<warning> %s", str);
	}


/* Converts a domain name in DNS message into string. The first value is a pointer to where the string will be placed. Second is the domain name's first byte */
/* The return value is the length of the string not including the terminating null character (like strlen) */
/* IMPORTANT: This function does not allocate memory for the string container, it must be done properly outside the function! */
int DnsToString(unsigned char* string, unsigned char* dns) {
	int i=0;
	int length=0;
	
	int next=dns[0];
	while(next != 0x00) {
		for(i=0; i<next; i++) { 
			string[length]=(char)dns[length+1];
			length++;
			}
		string[length++] = '.';
		next = dns[length];
		}
	string[--length] = '\0';
	
	return length;
}


/* Determine the storage size of the encoded domain name which starts at the given char array in the DNS message */
/* Note that this is by 2 chars longer than the return value of strlen() would be if the domain name were stored as a normal string */
int string_length(unsigned char *data) {

	if (data[0] >= 0xc0) { return 2; }  // If the searched string is a pointer the return value will be 2 (in bytes)
	
	int length=0;
	unsigned char chk=data[0];
	
	while(chk != 0x00) {
		length=length+chk+1;
		chk=data[length];
		}

	return length+1;
}


/* Thread for the complete handling of a request: sending IPv4 DNS query, receive the response, and convert it to IPv6, then send it back to the IPv6 client */
void send_response(char *client_ip, int client_port, unsigned char *dns64qry, int sock6fd, int recv6len, struct sockaddr_in6 dns64srv, ConfigModule& confmod) {

	int sockfd;     // Socket file descriptor
	int recvlen=0;  // Received packet length

	struct sockaddr_in dnssrv;  // IPv4 DNS address container
	socklen_t slen=sizeof(dnssrv);
	
	unsigned char *question;// This is used only in debug mode, for storing and printing the questioned domain name
	unsigned char *dns64rsp;// DNS64 response message to be sent (to the IPv6 only client)
	unsigned char *dnsrsp;  // Response message from IPv4 DNS server
	int next=0;    		// For indexing in dnsrsp

	unsigned short int store[32];	// Store where we pulled in extra data
	short int storeindex=0;		// For indexing in store array

	unsigned short int answblk;  	// The number of Answer blocks which can be found in the DNS server response message
	unsigned short int authblk;	// The number of Authority blocks which can be found in the DNS server response message
	unsigned short int addblk;	// The number of Additional blocks which can be found in the DNS server response message
	unsigned short int questionblk; // The size of the Question block
	unsigned short blockcount=0;	// For indexing the processed blocks
	unsigned plusdata=0;	// The amount of shifts performed (in byte) in the DNS64 response message. It is divisible with 12

	unsigned short type=0;	// Type of the actual block and temorary variable which stores two bytes from DNS 
	unsigned short int pointer=0;	// Stores two bytes from DNS message, temporary variable
	unsigned short tmp;       	// Temporary variable

	bool synth=false;

	struct timeval timeout; // For timeout settings

	
	/* If debugging mode is enabled the DNS message type will be checked and the questioned domain name will be stored */
	if (confmod.GetDebug()) {
		
		// If the first 5 bytes after the Transaction ID (which is QR and OPCODE) are zeros then it means this is a standard query
		tmp = dns64qry[2] << 8;
		tmp+= dns64qry[3];
		tmp = tmp >> 11; 		
		if (tmp != 0) syslog(LOG_WARNING, "<debugwarning> The received message is not a standard query");
		else { 
			// Store and print the queried domain name 
			tmp = string_length(dns64qry+12)-1;  // Recall that string_length() returns "strlen()+2" 
           		question = (unsigned char*)malloc( tmp*sizeof(unsigned char));
           		DnsToString(question, dns64qry+12); 
			syslog(LOG_INFO, "<debuginfo> The client sent a request for domain name: [%s]", question); 
			}
		}
		

	/* Check whether the DNS64 query message contains multiple questions */
	if (dns64qry[4] != 0x00 || dns64qry[5] != 0x01) { 
		syslog(LOG_WARNING, "Unsupported DNS format (Multiple Questions in DNS packet) [%s]", question);
		if (confmod.GetDebug()) free(question);
		/* Free the allocated memories */
		free(dns64qry); free(client_ip); 
		return;
		}

	/* Check whether the IPv6 client has sent a request which has "AAAA" type (0x001c) */
	type=12;
	type+=(string_length(dns64qry+type));
	if (dns64qry[type] == 0x00 && dns64qry[type+1] == 0x1c) { 

		synth = true;
		}


	/* Allocate memory for DNS message containers */
	dnsrsp= (unsigned char*)malloc((BUFLEN)*sizeof(unsigned char));  // IPv4 DNS response message container
	questionblk = 16+(string_length(dns64qry+12));  // Sets the size of the Question block which will be the same as in the response message
	dns64rsp= (unsigned char*)malloc(  max(confmod.GetResponseMaxLength() , questionblk  )*sizeof(unsigned char)  );  
	// If the Question block is bigger then the max respone length allocate at least for Question block
	

	/* Create a UDP socket */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1) logerror("socket() failure");

	/* Socket settings for sending out DNS query */
	bzero(&dnssrv, sizeof(dnssrv));
	dnssrv.sin_family = AF_INET;  // Address family
	dnssrv.sin_port = htons(53);  // UDP port number
	dnssrv.sin_addr.s_addr = inet_addr(confmod.GetDnsServer()); // Adding a DNS servers according to the selection-mode


	/* Send DNS query and receive DNS response */
	timeout.tv_sec = confmod.GetTimeoutSec();  // Setting up timeout values
	timeout.tv_usec = confmod.GetTimeoutUsec();
	if ( setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)) ) logerror("setsockopt() failed");

	
	/* Sending and resending DNS query */
	tmp = 0;
	while (tmp < confmod.GetResendAttempts()+1) {
		
		if (confmod.GetDebug()) {
			if (tmp !=0) syslog(LOG_INFO, "<debuginfo> --> Resending the DNS query [%s]", question);
			else syslog(LOG_INFO, "<debuginfo> Sending DNS query to remote server [%s]", question);
			}
		if ( sendto(sockfd, dns64qry, recv6len, 0, (struct sockaddr *)&dnssrv, sizeof(dnssrv)) == -1) logerror("sendto() failure");

		if ((recvlen = recvfrom(sockfd, dnsrsp, BUFLEN, 0, (struct sockaddr*)&dnssrv, &slen)) <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (confmod.GetDebug()) syslog(LOG_WARNING, "<debugwarning> No answer from remote DNS server [%s]", question);
				dnssrv.sin_addr.s_addr = inet_addr(confmod.GetDnsServer());
				tmp++;
				}
			else if (errno == EMSGSIZE) {
				syslog(LOG_WARNING, "<warning> The response message from IPv4 DNS server is longer than %d bytes. Ignodered [%s]", BUFLEN, question);
				if (confmod.GetDebug()) free(question);
				/* Free the allocated memories */
				free(dns64qry); free(client_ip); free(dnsrsp); free(dns64rsp);	
				return;
				}	
			else logerror("recvfrom() failure");
			}
		else {
			if (confmod.GetDebug()) syslog(LOG_INFO, "<debuginfo> Received DNS response message from remote server [%s]", question);
			break;
			}
		}

	// Check RCODE it the record has "AAAA" type
	if (synth) {
		// There is no such domain name no need to modify response message (RCODE=3 Name Error)
		if ((dnsrsp[3] % 0b1000) == 3) synth=false;
		else {
			// Check if the response contains Answer. If yes, no need to modify response message
			if (dnsrsp[6] != 0x0 || dnsrsp[7] != 0x0) {
				printf("Vanvalasz");
				synth=false;
				}
			// If there is no "AAAA" record then we should synthesize "AAAA" record from "A" recorde therfore we have to send another query
			}
		}

	// If there were no answer for the last DNS query
	if (tmp == confmod.GetResendAttempts()+1) {
		syslog(LOG_WARNING, "<warning> Ignoring this request since there were no answer from remote DNS server [%s]", question);
		close(sockfd);
		if (confmod.GetDebug()) free(question);
		/* Free the allocated memories */
		free(dns64qry); free(client_ip); free(dnsrsp); free(dns64rsp);	
		return;
		}


	if (synth) {
		dns64qry[type+1] = 0x01;
		tmp = 0;
		while (tmp < confmod.GetResendAttempts()+1) {
		
			if (confmod.GetDebug()) {
				if (tmp !=0) syslog(LOG_INFO, "<debuginfo> --> Resending the DNS query [%s]", question);
				else syslog(LOG_INFO, "<debuginfo> Sending DNS query to remote server [%s]", question);
				}
			if ( sendto(sockfd, dns64qry, recv6len, 0, (struct sockaddr *)&dnssrv, sizeof(dnssrv)) == -1) logerror("sendto() failure");

			if ((recvlen = recvfrom(sockfd, dnsrsp, BUFLEN, 0, (struct sockaddr*)&dnssrv, &slen)) <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					if (confmod.GetDebug()) syslog(LOG_WARNING, "<debugwarning> No answer from remote DNS server [%s]", question);
					dnssrv.sin_addr.s_addr = inet_addr(confmod.GetDnsServer());
					tmp++;
					}
				else if (errno == EMSGSIZE) {
					syslog(LOG_WARNING, "<warning> The response message from IPv4 DNS server is longer than %d bytes. Ignodered [%s]", BUFLEN, question);
					if (confmod.GetDebug()) free(question);
					/* Free the allocated memories */
					free(dns64qry); free(client_ip); free(dnsrsp); free(dns64rsp);	
					return;
					}	
				else logerror("recvfrom() failure");
				}
			else {
				if (confmod.GetDebug()) syslog(LOG_INFO, "<debuginfo> Received DNS response message from remote server [%s]", question);
				break;
				}
			}
		
		// If there were no answer for the last DNS query
		if (tmp == confmod.GetResendAttempts()+1) {
			syslog(LOG_WARNING, "<warning> Ignoring this request since there were no answer from remote DNS server [%s]", question);
			close(sockfd);
			if (confmod.GetDebug()) free(question);
			/* Free the allocated memories */
			free(dns64qry); free(client_ip); free(dnsrsp); free(dns64rsp);	
			return;
			}
		}
		

	// If there were no answer for the last DNS query
	if (tmp == confmod.GetResendAttempts()+1) {
		syslog(LOG_WARNING, "<warning> Ignoring this request since there were no answer from remote DNS server [%s]", question);
		close(sockfd);
		if (confmod.GetDebug()) free(question);
		/* Free the allocated memories */
		free(dns64qry); free(client_ip); free(dnsrsp); free(dns64rsp);	
		return;
		}
		

	close(sockfd);

	/* If it was originally an "AAAA" request MTD64 should synthesize "AAAA" records from "A" */
	/* It the type of the request is not "AAAA" not necessary to modify response message. We will jump to the sending process */
	if (synth) {
	
	memcpy(dns64rsp, dnsrsp, max(confmod.GetResponseMaxLength() , questionblk  ) );  // Copy the response message to dns64rsp which will be edited and sent
	dns64rsp[type+1] = 0x1c;

	next=12;  // This is where Question block starts
	next+=(string_length(dnsrsp+next));  // Jump up Name value
	next+=4;  // Jump up Type and Class value, this is the end of Question block


	/* Setting the block numbers from the IPv4 DNS server response message into variables */
	answblk = dnsrsp[6] << 8;  // Sets the number of Answer blocks
	answblk+= dnsrsp[7];
	authblk = dnsrsp[8] << 8;  // Sets the number of Authority blocks
	authblk+= dnsrsp[9];
	addblk  = dnsrsp[10] << 8; // Sets the number of Additional blocks
	addblk += dnsrsp[11];

	// Examine the blocks in the IPv4 respone message and modify the necessary changes
	while ( blockcount < answblk+authblk+addblk ) { 

		/* Check whether addig a new block will cause too big size (more then confmod.GetResponseMaxLenth()) for dns64rsp */
		// Sets the size of next block
		tmp = (string_length(dnsrsp+next));  // Length of the Name field
		pointer = dnsrsp[next+10];	// This is the RDATA length
		pointer = pointer << 8;
		pointer+= dnsrsp[next+11];
		if (dnsrsp[next+2] == 0x00 && dnsrsp[next+3]==0x01) pointer+=12; // If the record type is "A" it will be changed to "AAAA" therefore we need 12 bytes additional space 

		// Sums current length of the dns64rsp (plusdata+next) and the length of this block (tmp(Name field) + 10 (Type,Class,TTL,DLEN) + pointer (RDATA length)
		// and it will be compared with the size of the IPv6 response message maximum length. If the first is bigger, cut off is necessary.
		if ( plusdata+next+tmp+10+pointer > (unsigned int)confmod.GetResponseMaxLength() ) {

			// If there is a cut off, the number of blocks have to be modified accordingly
			syslog(LOG_WARNING, "<warning> A DNS64 response message has been truncated. The number of the last block is: %d [%s]", blockcount, question);
			if (confmod.GetDebug()) syslog(LOG_WARNING, "<debugwarning> %d block has been cut off. %d additinal bytes needed for the next block [%s]", answblk+authblk+addblk-blockcount, (plusdata+next+tmp+10+pointer)-confmod.GetResponseMaxLength(), question);

			// We have to modify the block counters in the Question block
			if (blockcount < answblk) {
				dns64rsp[7] = blockcount;	// Answer block counter
				dns64rsp[9] = 0x00;		// Authority block counter
				dns64rsp[11]= 0x00;		// Additional block counter
				}
			else if (blockcount < answblk+authblk) {
				dns64rsp[9] = blockcount-answblk;// Authority block counter
				dns64rsp[11]= 0x00;		 // Additional block counter
				}
			else if (blockcount < answblk+authblk+addblk) {
				dns64rsp[11]= blockcount-answblk-authblk;  // Additional block counter
				}
			break;
			}
		
		/* If the new block fits in, continue processing */
		next+=tmp;  // Adds the length of the actual block's Name field
		
		// Additional block could contain poniter in Name field which may need to be modified (Answer and Authority has always c00c therefore shouldn't be changed)
		if (blockcount >= answblk+authblk) {

			pointer = dnsrsp[next-2];  // Sets the pervious 2 byte's value to variable
			pointer = pointer << 8;
			pointer+= dnsrsp[next-1]; 
			
			// Check wheter it is a pointer
			if ( pointer >= 0xc000 ) {
				tmp=0;

				while (storeindex!=tmp) {
					if (pointer-0xc000 >= store[tmp]) tmp++;
					else break;
					}

				if (type!=0) {
				
					if (confmod.GetDebug()) syslog(LOG_INFO, "<debuginfo> Modifying pointer in block %d NAME FIELD %04x to %04x [%s]", blockcount+1, pointer, pointer+tmp*12, question);
					dns64rsp[plusdata+next-2] = (pointer+tmp*12) >> 8;
					dns64rsp[plusdata+next-1] = (pointer+tmp*12) % 0x100;
					}
				
				}		
			}

		type = dnsrsp[next++] << 8;  // Sets the block's Type value
		type+= dnsrsp[next++];

		/* Check whether it is an "A" record If it is, convert it to an "AAAA" record */
		if (type == 0x0001) {

				
			if (confmod.GetDebug()) syslog(LOG_INFO, "<debuginfo> Found: type \"A\" in block %d, modifying it to \"AAAA\" [%s]", blockcount+1, question);
			/* Synthetsize the IPv4 embedded IPv6 address */
			dns64rsp[plusdata+next-2]=0x00;  // Setting type value to AAAA
			dns64rsp[plusdata+next-1]=0x1c;

			dns64rsp[plusdata+next+6]=0x00;  // Setting data length to 16
			dns64rsp[plusdata+next+7]=0x10;
			
			store[storeindex++]=next+14;     // Store where we put extra data
			confmod.SetIpv4eIpv6Addr(dns64rsp+plusdata+next+8, dnsrsp+next+8 );

			// Append the rest of the data from original DNS response message
			memcpy(dns64rsp+(plusdata+next+24), dnsrsp+(next+12), max(0,confmod.GetResponseMaxLength()-(plusdata+next+24)) );
			plusdata+=12;
			}
		
 
		next+=6;			// Jump up CLASS and TTL values of the actual block 
		tmp = dnsrsp[next++]<< 8;  	// Sets the data length of the actual block                          
		tmp+= dnsrsp[next++];
		next+= tmp;			// Jump to the data field's end
			
			
		pointer = dnsrsp[next-2]; 	// Sets the last 2 byte's value to variable
		pointer = pointer << 8;
		pointer+= dnsrsp[next-1]; 

		// Data field must be a string which could contain pointer at the end
		// If it is a pointer, value changes may needed due to possible data pull in
		if (pointer >= 0xc000 ) {
			tmp=0;

			while (storeindex!=tmp) {
				if (pointer-0xc000 >= store[tmp]) tmp++;
				else break;
				}

			if (tmp!=0) {
				
				if (confmod.GetDebug()) syslog(LOG_INFO, "<debuginfo> Modifying pointer in block %d RDATA field: %04x to %04x [%s]", blockcount+1, pointer, pointer+tmp*12, question);
				dns64rsp[plusdata+next-2] = (pointer+tmp*12) >> 8;
				dns64rsp[plusdata+next-1] = (pointer+tmp*12) % 0x100;
				}
			
			}	
		blockcount++;  // One block is completed
		}
		recvlen = next+plusdata;
		}
	

	/* Sending the assembled dns64response to the IPv6 client */
	inet_pton(AF_INET6, client_ip, &dns64srv.sin6_addr.s6_addr);
	dns64srv.sin6_port = htons(client_port);

	// If we had to synthesize AAAA records we will send dns64rsp
	if (synth) { if ( sendto(sock6fd, dns64rsp, recvlen, 0, (struct sockaddr *)&dns64srv, sizeof(dns64srv)) == -1) logerror("sendto() failure"); }
	// If there were no changes in the DNS Response message we will send dnsrsp
	else { if ( sendto(sock6fd, dnsrsp, recvlen, 0, (struct sockaddr *)&dns64srv, sizeof(dns64srv)) == -1) logerror("sendto() failure"); }

	if (confmod.GetDebug()) { 
		syslog(LOG_INFO, "<debuginfo> Response has been sent back to %s Port: %d Length: %d [%s]", client_ip, ntohs(dns64srv.sin6_port), recvlen, question);
		free(question);
		}

	/* Free the allocated memories */
	free(dns64qry); free(dnsrsp); free(dns64rsp);	
	return;
}



int main() {

	int sock6fd;  // Socket file descriptor
	int recvlen;  // Received packet legth

	struct sockaddr_in6 dns64srv;  	// Own address
	socklen_t slen=sizeof(dns64srv);// Legth of adresses
	unsigned char buf[BUFLEN]; 	// Packet data container
	char *client_ip;		// IPv6 address of the request originator client
	unsigned char *dns64qry;
	
	ConfigModule confmod;		// Initialize the config module

	/* Preparing a syslog facility LOG_DAEMON for the program to log */
	openlog ("DNS64SERVER", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_INFO, "<info> Program started by User %d", getuid ());

	/* Loads configuration from file and sets the number of DNS servers */
	load_config(confmod);

	/* Create a UDP socket */
	if ((sock6fd = socket(AF_INET6, SOCK_DGRAM, 0))==-1) logerror("socket() failure");

	/* Socket settings for receiving DNS64 queries */
	bzero(&dns64srv, sizeof(dns64srv));
	dns64srv.sin6_family = AF_INET6;  // Address family
	dns64srv.sin6_port = htons(53);   // UDP port number
	dns64srv.sin6_addr = in6addr_any; // To any valid IP address


	/* Bind the socket */
	if (bind(sock6fd, (struct sockaddr* ) &dns64srv, sizeof(dns64srv))==-1) logerror("bind() faliure");
	else loginfo("DNS64SERVER has been started successfully");

	/* Loop for receiving UDP packets */
	while(1) {

		if ( (recvlen = recvfrom(sock6fd, buf, sizeof buf, 0, (struct sockaddr*)&dns64srv, &slen)) <= 0) {
			if (errno == EMSGSIZE) {
				syslog(LOG_WARNING, "<warning> The received message from IPv6 client is longer than %d bytes. Ignodered", BUFLEN);
				continue;
				}
			else logerror("recvfrom() faliure");
			}

		// Allocate containter for the IPv6 client
		client_ip = (char*)malloc(INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &dns64srv.sin6_addr, client_ip, INET6_ADDRSTRLEN);

		if (confmod.GetDebug()) syslog(LOG_INFO, "<debuginfo> Received a packet from %s | Port: %d Length: %d", client_ip, ntohs(dns64srv.sin6_port), recvlen);
	
		// Allocate container for DNS64 query which will be edited within a separate thread
		dns64qry = (unsigned char*)malloc(recvlen*sizeof(unsigned char));
		memcpy(dns64qry,buf,recvlen);

		// Open thread for converting DNS64 query to IPv4 DNS query which will be sent.
		// After the response arrived IPv4 embedded IPv6 address will be synthesized if necessary and reply will be sent to the client
		std::thread t(send_response, client_ip, ntohs(dns64srv.sin6_port), dns64qry, sock6fd, recvlen, dns64srv, std::ref(confmod));
		t.detach();
	

		}

	close(sock6fd);
	return 0;
	}


