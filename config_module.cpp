#include "header.h"

ConfigModule::ConfigModule(void) {

	rr = 0;			// The sequence number of the DNS server which is actually in use in round-robin mode
	sel_mode = 0;		// DNS server selection mode: (1) means round-robin, (2) means random
	servercount = 0; 	// Number of DNS servers
	
	ipv6_prefix = 0;	// Prefix length for IPv4 embedded IPv6 addresses
	timeout_time_sec = 0;	// DNS response packet arrival expectation time in seconds before resending the query message
	timeout_time_usec = 0;	// DNS response packet arrival expectation time in micro-seconds before resending the query message 
	resend_attempts = -1;
	response_maxlength = 0; // The maximum length of IPv6 DNS response message
	
	gettimeofday(&time,NULL);  	// Setting up the random number generator
	srand((time.tv_sec * 1000) + (time.tv_usec / 1000));
	strcpy(ipv6_address, "::1");	// This value means ipv6_address has not been set in configuration file
					
	debug=false;			// By default debug is off

}


void ConfigModule::AddDNSServer(char* ip) {
	if ( servercount > MAX_DNS_SERVERS ) logwarning("Config WARNING: The maximum number of DNS server has been reached");
	else {
		if ( strcmp(ip,"0.0.0.0") ) {
			strcpy(dns_servers[servercount++], ip);
			syslog(LOG_INFO, "<info> Added DNS server IP: %s (#%d)", ip, servercount);
			}
		}
	return;
	}
	

void ConfigModule::SetSelectionMode(short int x) {

	if (x == 1) loginfo("DNS server selection mode has been set to round-robin");
	else if (x == 2) loginfo("DNS server selection mode has been set to random");
	else logerror("Config ERROR: Invalid selection mode found");
	sel_mode = x;
	}


short int ConfigModule::GetSelectionMode() {
	return sel_mode;
	}


void ConfigModule::SetPrefix(short int x) {
	ipv6_prefix = x;
	if (ipv6_prefix != 32 && ipv6_prefix != 40 && ipv6_prefix != 48 && ipv6_prefix != 56 && ipv6_prefix != 64 && ipv6_prefix != 96) 
		logerror("Config ERROR: Invalid DNS64 IPv6 prefix found in configuration file. Usable NDS64 prefix length values are: 32,40,48,56,64,96");
	syslog(LOG_INFO, "<info> DNS64 prefix length has been set to: %d", ipv6_prefix);
	}


short int ConfigModule::GetPrefix() {
	return ipv6_prefix;
	}


/* Create template for IPv4 embedded IPv6 address  */
void ConfigModule::SetIpv6Addr(char* x) {
	int i, l;
	char str[50];
	if (inet_pton(AF_INET6, x, &checkedipv6)) {

		if 	( ipv6_prefix == 96 ) for (i = 12;i<=15; i++) checkedipv6.s6_addr[i]=0x0;
		else if ( ipv6_prefix == 64 ) for (i = 8; i<=15; i++) checkedipv6.s6_addr[i]=0x0;
		else if ( ipv6_prefix == 56 ) for (i = 7; i<=15; i++) checkedipv6.s6_addr[i]=0x0;
		else if ( ipv6_prefix == 48 ) for (i = 6; i<=15; i++) checkedipv6.s6_addr[i]=0x0;
		else if ( ipv6_prefix == 40 ) for (i = 5; i<=15; i++) checkedipv6.s6_addr[i]=0x0;
		else if ( ipv6_prefix == 32 ) for (i = 4; i<=15; i++) checkedipv6.s6_addr[i]=0x0;
		else logerror("Config ERROR: Invalid IPv6 prefix found in configuration file");

		/* Print the template for the IPv4 embedded IPv6 addresses into syslog*/
		i=0;
		for(l=1; l<=(ipv6_prefix/4)+(ipv6_prefix/16); l++) str[i++]=' ';
		str[i++]='v';
		str[i++]='\0';

		if ( ipv6_prefix == 96 ) strcat(str, "       v\n");
		else strcat(str,"          v\n");

		syslog(LOG_INFO, "<info> Template for the IPv4 embedded IPv6 addresses:");
		syslog(LOG_INFO, "<info> %s", str);
  
		sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", (int)checkedipv6.s6_addr[0], (int)checkedipv6.s6_addr[1], (int)checkedipv6.s6_addr[2], (int)checkedipv6.s6_addr[3], (int)checkedipv6.s6_addr[4], (int)checkedipv6.s6_addr[5], (int)checkedipv6.s6_addr[6], (int)checkedipv6.s6_addr[7], (int)checkedipv6.s6_addr[8], (int)checkedipv6.s6_addr[9], (int)checkedipv6.s6_addr[10], (int)checkedipv6.s6_addr[11], (int)checkedipv6.s6_addr[12], (int)checkedipv6.s6_addr[13], (int)checkedipv6.s6_addr[14], (int)checkedipv6.s6_addr[15]);
		syslog(LOG_INFO, "<info> %s", str);
		
		i=0;
		for(int l=1; l<=(ipv6_prefix/4)+(ipv6_prefix/16); l++) str[i++]=' ';
		str[i++]='^';
		str[i++]='\0';
		
		if ( ipv6_prefix == 96 ) strcat(str,"       ^\n");
		else strcat(str,"          ^\n");
		syslog(LOG_INFO, "<info> %s", str);
		
		}
	else logerror("Config ERROR: Invalid IPv6 prefix found in configuration file");
	strcpy(ipv6_address, x);
	}


char* ConfigModule::GetIpv6Addr() {
	return ipv6_address;
	}


short int ConfigModule::GetServerCount() {
	return servercount;
	}


void ConfigModule::SetDebug(bool i) {
	if (i == true) { 
		loginfo("Debugging mode has been turned ON");
		debug = true;
		}
	else debug = false;
	}


bool ConfigModule::GetDebug() {
	return debug;
	}

/* Returns with a DNS server IPv4 address according to the server selection mode setting */
char* ConfigModule::GetDnsServer() {
	if (sel_mode == 2) return dns_servers[rand()%servercount];
	
	else if (sel_mode == 1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {  // If DNS response did not arrive in time 
			if (rr+1 == servercount) rr=0;
			else rr++;
			if (debug) syslog(LOG_WARNING, "<warning> Switched DNS server to [%d] : %s", rr, dns_servers[rr]);
			}
		return dns_servers[rr];
		}
	else logerror("Invalid Selection Mode value found");    // This shoul not supposed to happen, exits
	return const_cast<char*>("0"); // Just for the compiler, this code is never reached
}


/* Assembly the IPv4 embedded IPv6 address */
void ConfigModule::SetIpv4eIpv6Addr(unsigned char* pointer, unsigned char* ipv4ptr) {

	if ( ipv6_prefix == 96 ) {
		memcpy(pointer, checkedipv6.s6_addr, 12);
		pointer[12] = ipv4ptr[0];
		pointer[13] = ipv4ptr[1];	
		pointer[14] = ipv4ptr[2];
		pointer[15] = ipv4ptr[3];
		}

	else if ( ipv6_prefix == 64 ) {
		memcpy(pointer, checkedipv6.s6_addr, 16);
		pointer[8] = 0x0;
		pointer[9] = ipv4ptr[0];
		pointer[10] = ipv4ptr[1];
		pointer[11] = ipv4ptr[2];
		pointer[12] = ipv4ptr[3];
		}
	
	else if ( ipv6_prefix == 56 ) {
		memcpy(pointer, checkedipv6.s6_addr, 16);
		pointer[7] = ipv4ptr[0];
		pointer[8] = 0x0;
		pointer[9] = ipv4ptr[1];
		pointer[10] = ipv4ptr[2];
		pointer[11] = ipv4ptr[3];
		}

	else if ( ipv6_prefix == 48 ) {
		memcpy(pointer, checkedipv6.s6_addr, 16);
		pointer[6] = ipv4ptr[0];
		pointer[7] = ipv4ptr[1];
		pointer[8] = 0x0;
		pointer[9] = ipv4ptr[2];
		pointer[10] = ipv4ptr[3];
		}

	else if ( ipv6_prefix == 40 ) {
		memcpy(pointer, checkedipv6.s6_addr, 16);
		pointer[5] = ipv4ptr[0];
		pointer[6] = ipv4ptr[1];
		pointer[7] = ipv4ptr[2];
		pointer[8] = 0x0;
		pointer[9] = ipv4ptr[3];
		}

	else if ( ipv6_prefix == 32 ) {
		memcpy(pointer, checkedipv6.s6_addr, 16);
		pointer[4] = ipv4ptr[0];
		pointer[5] = ipv4ptr[1];
		pointer[6] = ipv4ptr[2];
		pointer[7] = ipv4ptr[3];
		pointer[8] = 0x0;
		}

	return;
}


/* Timeout Time Sec settings */
void ConfigModule::SetTimeoutSec(char* num) {
	long int tmp;
	tmp = atoi(num);
	if (tmp > 32767) { 
		logwarning("Config WARNING: timeout-time-sec value is above 32767. Setting timeout-time-sec value to maximum");
		timeout_time_sec = 32767;
		}
	else if (tmp >= 0) timeout_time_sec = tmp;
	else logwarning("Config WARNING: Invalid timeout-time-sec value found. Ignored");
	return;
	}


int ConfigModule::GetTimeoutSec() {
	return timeout_time_sec;
	}


/* Timeout Time Usec settings */
void ConfigModule::SetTimeoutUsec(char* num) {
	long int tmp;
	tmp = atoi(num);
	if (tmp >= 0 && tmp < 1000000) timeout_time_usec = tmp;
	else logwarning("Config WARNING: Invalid timeout-time-usec value found. Ignored");
	return;
	}


int ConfigModule::GetTimeoutUsec() {
	return timeout_time_usec;
	}


/* Resend Attempts settings */
void ConfigModule::SetResendAttempts(char* num) {
	int tmp;
	tmp = atoi(num);
	if (tmp > 32767) { 
		logwarning("Config WARNING: resend-attempts value is above 32767. Setting resend-attepmpts value to maximum");
		resend_attempts = 32767;	
		syslog(LOG_INFO, "<info> Number of resend attempts has been set to: %d", resend_attempts);
		}
	else if (tmp >= 0) { 
		resend_attempts = tmp;
		syslog(LOG_INFO, "<info> Number of resend attempts has been set to: %d", resend_attempts);
		}
	else logwarning("Config WARNING: Invalid resend-attempts value found. Ignored");
	return;
	}


int ConfigModule::GetResendAttempts() {
	return resend_attempts;
	}


/* Maximum length of the IPv6 response message settings */
void ConfigModule::SetResponseMaxLength(char* num) {
	int tmp;
	tmp = atoi(num);
	if (tmp > 32767) { 
		logwarning("Config WARNING: response-maxlength value is above 32767. Setting response-maxlength value to 512 bytes");
		response_maxlength = 512;
		syslog(LOG_INFO, "<info> Maximum length of the IPv6 response message (UDP payload) has been set to: %d bytes", response_maxlength);
		}

	else if (tmp >= 512) { 
		response_maxlength = tmp;
		if (tmp != 512) logwarning("Config WARNING: The set of the the maximum length of the IPv6 response message is NOT the recommended value (which is 512). Programs could discard messages greater than 512 bytes!");
		syslog(LOG_INFO, "<info> Maximum length of the IPv6 response message (UDP payload) has been set to: %d bytes", response_maxlength);
		}

	else if (tmp < 512) {
		logwarning("Config WARNING: The set of the maximum length of the IPv6 response message is NOT the recommended value (which is 512). Response messages could be truncated!");
		response_maxlength = tmp;
		syslog(LOG_INFO, "<info> Maximum length of the IPv6 response message (UDP payload) has been set to: %d bytes", response_maxlength);
		}
	else logwarning("Config WARNING: Invalid response-maxlength value found. Ignored");
	return;
	}


int ConfigModule::GetResponseMaxLength() {
	return response_maxlength;
	}


