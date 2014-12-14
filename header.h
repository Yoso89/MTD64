/* header.h */
#ifndef HEADERFILE_H
#define HEADERFILE_H
#define MAX_DNS_SERVERS 50
#define BUFLEN 512

#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h> 
#include <string.h>
#include <sys/time.h>
#include <resolv.h>
#include <syslog.h>

/* This class stores all the setting of the DNS64 server */
class ConfigModule {
private:
	int rr;  			// The sequence number of the DNS server which is actually in use in round-robin mode
	char dns_servers[MAX_DNS_SERVERS][16];   	// IPv4 addresses of DNS name servers 
	short int servercount;		// Number of DNS servers
	short int sel_mode;  		// DNS server selection mode: (1) means round-robin, (2) means random

	char ipv6_address[INET6_ADDRSTRLEN];		// IPv6 address container
	struct in6_addr checkedipv6;	// For checking if the address is valid, and used later for conversion, too
	short int ipv6_prefix;		// Prefix length for IPv4 embedded IPv6 addresses
	
	struct timeval time;		// For timeout settings

	short int timeout_time_sec;	// DNS response packet arrival expectation time in seconds before resending the query message
	long int timeout_time_usec;	// DNS response packet arrival expectation time in micro-seconds before resending the query message

	short int resend_attempts;	// 0 = no resending attempt

	char default_interface[10];	// Default sending interface's name container

	short int response_maxlength;	// Maximum legth of the IPv6 DNS response packet (UDP payload)

	bool debug;

public:
	ConfigModule();			// Constructor 
	void AddDNSServer(char*);

	void SetSelectionMode(short int);// Sets DNS server selection mode
	short int GetSelectionMode();

	void SetPrefix(short int);	// Loads the prefix for the IPv4 embedded IPv6 addresses from the configuration file
	short int GetPrefix();

	void SetIpv6Addr(char*);	// Creating template for the IPv4 embedded IPv6 address
	char* GetIpv6Addr();

	void SetIpv4eIpv6Addr(unsigned char*, unsigned char*);  // Assembly the IPv4 embedded IPv6 address

	short int GetServerCount(); 	// Returns the neumber of the definied DNS servers

	char* GetDnsServer();		// Returns an IPv4 address which will be used for sending DNS query

	void SetDebug(bool);			
	bool GetDebug();

	void SetTimeoutSec(char*);	// Sets the DNS response packet timeout before resending the query message
	int GetTimeoutSec();	

	void SetTimeoutUsec(char*);	// Like above, in micro-seconds unit
	int GetTimeoutUsec();

	void SetResponseMaxLength(char*);  // Sets the maximum length of IPv6 DNS response message
	int GetResponseMaxLength();

	void SetResendAttempts(char*);
	int GetResendAttempts();

};

/* Prototypes */

void load_config(ConfigModule& a);	// Responsible for loading configurations from file
int DnsToString(unsigned char* string, unsigned char* dns);  // Converts a DNS message domain name into string

// Logging and error handling function
void loginfo(const char str[]); 
void logerror(const char str[]);
void logerror(const char str[], int line);
void logwarning(const char str[]);

#endif
