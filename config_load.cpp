#include "header.h"


void load_config(ConfigModule& confmod) {
	
	int i,k,tmp=0;		// Temporary variables 
	char string_buffer[16];	// 16 bytes long container, could store IPv4 address
	char ipv6_address[40];	// IPv6 address container
	int linecount=1;	// Line counter for the opened config file
	char line[255];		// Store one line for config file
	char tmpline[255];	// temoporary array for storing comments
	struct in_addr checkip;	// This is need for to decide whether it is a valid IPv4 address 

	/* Open configuration file and read it line by line */
	FILE *file = fopen("settings.conf", "r");
	if ( file != NULL ) {
		for ( ; fgets( line, sizeof line, file) != NULL; linecount++) {

			// If a line is a comment, processsing is not necessary
			if (strlen(line) < 3 || line[0] == '#' || (line[0] == '/' && line[1] == '/')) {
				while ((strlen(line) == 254) && line[254] != 10) {
					if ( fgets( line, sizeof line, file) == NULL) { 
						loginfo("Configuration file has been successfully loaded");
						return;
						}
					}
				continue;
				}

			// If a line is not a comment, but longer than 254 characters, the first 254 characters will be passed to the command processing, and the rest of the data will be ignored
			if ((strlen(line) == 254) && line[254] != 10) {
				strcpy(tmpline,line);
				while((strlen(line) == 254 && line[254] != 10)) {
					if ( fgets( line, sizeof line, file) == NULL) {
						loginfo("Configuration file has been successfully loaded");
						return;
						}
					}
				strcpy(line,tmpline);
				}


			i=0;
			tmp=0;
			while ( line[i] == ' ' || line[i] == 9 ) i++; // Skip spaces and tabs 


			/* Look for "nameserver" setting in configuration file */
			if ( !strncmp(line+i, "nameserver", strlen("nameserver")) ) {
				i += strlen("nameserver");
				while ( line[i] == ' ' || line[i] == 9 ) i++;
	
				// Adding system default DNS servers
				if ( !strncmp(line+i, "defaults", strlen("defaults")) ) {
					res_init();
					for (k = 0; k<_res.nscount; k++)  { confmod.AddDNSServer(inet_ntoa(_res.nsaddr_list[k].sin_addr)); }
					continue;
					}
				
				
				/* Adding an IPv4 address */
				// ASCII values 48-57 represents numbers, 46 represents dot
				if (!(line[i] >= 48 && line[i] <= 57)) {	
					syslog(LOG_WARNING, "<warning> Invalid IP address found at line %d. Ignored", linecount);
					continue;
					}
				while ((line[i] >= 48 && line[i] <= 57) || line[i] == 46) {
					string_buffer[tmp]=line[i];
					i++;
					tmp++;
					if ( tmp > 15 )  {
						syslog(LOG_WARNING, "<warning> Invalid IP address found at line %d. Ignored", linecount);
						continue;
						}
					}

				string_buffer[tmp]='\0';

				// Check whether it is a valid IPv4 address		
				if (inet_pton(AF_INET, string_buffer, &(checkip.s_addr))) {

					confmod.AddDNSServer(string_buffer);
					continue;
					}
	
				else { 
					syslog(LOG_WARNING, "<warning> Invalid IP address found at line %d. Ignored", linecount);
					continue;
					}			

				}


			/* Look for DNS server selection mode settings in configuration file */
			else if ( !strncmp(line+i, "selection-mode", strlen("selection-mode")) ) {
				if (confmod.GetSelectionMode() == 1 || confmod.GetSelectionMode() == 2) {  // Check whether this setting has been already configured
					syslog(LOG_WARNING, "<warning> Config WARNING: Multiple selection-mode settings found at line %d. The first setting will be used", linecount);
					continue;
					}

				i += strlen("selection-mode");
				while ( line[i] == ' ' || line[i] == 9 ) i++; // Skip spaces and tabs 

				// Setting up round-robin DNS server selection mode
				if ( !strncmp(line+i, "round-robin", strlen("round-robin")) ) {
					confmod.SetSelectionMode(1);
					continue;
				}

				// Setting up random DNS server selection mode
				if ( !strncmp(line+i, "random", strlen("random")) ) {
					confmod.SetSelectionMode(2);
					continue;
				}

				else { 
					syslog(LOG_WARNING, "<warning> Config WARNING: Invalid DNS server selection mode found at line %d. Ignored", linecount);
					continue;
					}
				}


			/* Look for DNS64 prefix settings in configuration file */
			else if ( !strncmp(line+i, "dns64-prefix", strlen("dns64-prefix")) ) {
				if (strcmp(confmod.GetIpv6Addr(), "::1")) {  // Check whether this setting has been already configured
					syslog(LOG_WARNING, "<warning> Config WARNING: Multiple DNS64 address settings found at line %d. The first setting will be used", linecount);
					continue;
					}	
					

				i += strlen("dns64-prefix");
				while ( line[i] == ' ' || line[i] == 9 ) i++; // Skip spaces and tabs 


				// Adding IPv6 address and prefix //
				// ASCII values 48-57 represents numbers, 47 represents slash, 58 represents colon, 65-77 and 97-102 represents hexa characters a-F
				if (!((line[i] >= 47 && line[i] <= 58) || ( line[i] >= 65 && line[i] <= 77 ) || ( line[i] >= 97 && line[i] <= 102 )))  {
					syslog(LOG_WARNING, "<warning> Invalid DNS64 IPv6 address found in configuration file at line %d. Ignored", linecount);
					continue;
					}


				while ((line[i] >= 47 && line[i] <= 58) || ( line[i] >= 65 && line[i] <= 77 ) || ( line[i] >= 97 && line[i] <= 102 ))  {
					if ( tmp > 45 )	{
						syslog(LOG_WARNING, "<warning> Invalid DNS64 IPv6 address found in configuration file at line %d. Ignored", linecount);
						continue;
						}
						
					if (line[i+1] == 47) {
						// Checking first digit
					 	if (line[i+2] >= 49 && line[i+2] <= 57) {
							// Checking second digit
							if (line[i+3] >= 48 && line[i+3] <= 57) {
								if (line[i+4] != ' ' && line[i+4] != 9 && line[i+4] != '\0' && line[i+4] != 10) {
									syslog(LOG_WARNING, "<warning> Config WARNING: Invalid IPv6 prefix found in configuration file at line %d. Ignored", linecount);
									continue;
									} 									
								// Prefix validity check is inside the SetPrefix function
								confmod.SetPrefix( atoi(line+i+2) );
								ipv6_address[tmp++]=line[i++];
								break;
								}

							// If Prefix consist of only one digit
							else { 
								syslog(LOG_WARNING, "<warning> Config WARNING: Invalid IPv6 prefix found in configuration file at line %d. Ignored", linecount);
								continue;
								}	
							}
						else {
							syslog(LOG_WARNING, "<warning> Config WARNING: Invalid IPv6 prefix found in configuration file at line %d. Ignored", linecount);
							continue;
							}
						}
					ipv6_address[tmp]=line[i];
					i++;
					tmp++;
					}

				ipv6_address[tmp]='\0';

				// Setting IPv6 address, validity check is inside the function
				confmod.SetIpv6Addr( ipv6_address );
				continue;
				}


			/* Look for debugging settings in configuration file */
			else if ( !strncmp(line+i, "debugging", strlen("debugging")) ) {
				if (confmod.GetDebug()) continue;
				i += strlen("debugging");
				while ( line[i] == ' ' || line[i] == 9 ) i++; // Skip spaces and tabs 

				// Turn on debugging
				if ( !strncmp(line+i, "yes", strlen("yes")) ) {
					confmod.SetDebug(true);
					continue;
					}

				// Turn of debugging
				else if ( !strncmp(line+i, "no", strlen("no")) ) {
					confmod.SetDebug(false);
					continue;
					}
				
				else {
					syslog(LOG_WARNING, "<warning> Config WARNING: Unrecognised debugging parameter at line %d", linecount);
					confmod.SetDebug(false);
					continue;
					}
				}


			/* Look for timeout-time-sec settings in configuration file */
			else if ( !strncmp(line+i, "timeout-time-sec", strlen("timeout-time-sec")) ) {
				if (confmod.GetTimeoutSec() != 0) {  // Check whether this setting has been already configured
					syslog(LOG_WARNING, "<warning> Config WARNING: Multiple timeout-time-sec settings found at line %d. The first setting will be used", linecount);
					continue;
					}
			
				i += strlen("timeout-time-sec");
				while ( line[i] == ' ' || line[i] == 9 ) i++; // Skip spaces and tabs
				
				// ASCII values 48-57 represents numbers
				if ( !((line[i] >= 48 && line[i] <= 57)) ) {
					syslog(LOG_WARNING, "<warning> Config WARNING: Invalid timeout-time-sec value found in configuration file at line %d. Igonred", linecount);
					continue;
					}
				while ((line[i] >= 48 && line[i] <= 57)) { 
					if ( tmp > 5 )  {
						syslog(LOG_WARNING, "<warning> Config WARNING: Invalid timeout-time-sec value found in configuration file at line %d. Igonred", linecount);
						continue;
						}
					string_buffer[tmp++] = line[i++]; 
					}
				string_buffer[tmp]='\0';
				
				confmod.SetTimeoutSec(string_buffer);
				}
				

			/* Look for timeout-time-usec (micro) settings in configuration file */
			else if ( !strncmp(line+i, "timeout-time-usec", strlen("timeout-time-usec")) ) {
				if (confmod.GetTimeoutUsec() != 0) {  // Check whether this setting has been already configured
					syslog(LOG_WARNING, "<warning> Config WARNING: Multiple timeout-time-usec settings found at line %d. The first setting will be used", linecount);
					continue;
					}
			
				i += strlen("timeout-time-usec");
				while ( line[i] == ' ' || line[i] == 9 ) i++; // Skip spaces and tabs
			
				// ASCII values 48-57 represents numbers
				if ( !((line[i] >= 48 && line[i] <= 57)) ) {
					syslog(LOG_WARNING, "<warning> Config WARNING: Invalid timeout-time-sec value found in configuration file at line %d. Igonred", linecount);
					continue;
					}
				while ((line[i] >= 48 && line[i] <= 57)) {
					if ( tmp > 9 )  {
						syslog(LOG_WARNING, "<warning> Config WARNING: Invalid timeout-time-usec value found in configuration file at line %d. Igonred", linecount);
						continue;
						}
					string_buffer[tmp++] = line[i++];
					}
				string_buffer[tmp]='\0';
				confmod.SetTimeoutUsec(string_buffer);
				}


			/* Look for resend-attempts settings in configuration file */
			else if ( !strncmp(line+i, "resend-attempts", strlen("resend-attempts")) ) {
				if (confmod.GetResendAttempts() != -1 ) {
					syslog(LOG_WARNING, "<warning> Config WARNING: Multiple resend-attempts settings found at line %d. The first setting will be used", linecount);
					continue;
					}
				i += strlen("resend-attempts");
				while ( line[i] == ' ' || line[i] == 9 ) i++; // Skip spaces and tabs

				// ASCII values 48-57 represents numbers
				if ( !((line[i] >= 48 && line[i] <= 57)) ) {
					syslog(LOG_WARNING, "<warning> Config WARNING: Invalid timeout-time-sec value found in configuration file at line %d. Igonred", linecount);
					continue;
					}
				while ((line[i] >= 48 && line[i] <= 57)) {
					if ( tmp > 4 )  {
						syslog(LOG_WARNING, "<warning> Config WARNING: Invalid resend-attempts value found in configuration file at line %d. Igonred", linecount);
						continue;
						}
					string_buffer[tmp++] = line[i++];
					}
				string_buffer[tmp]='\0';
				confmod.SetResendAttempts(string_buffer);  // Try to set the loaded value
				}


			/* Look for ipv6response-maxlength settings in configuration file */
			else if ( !strncmp(line+i, "response-maxlength", strlen("response-maxlength")) ) {
				if (confmod.GetResponseMaxLength() != 0) {  // Check whether this setting has been already configured
					syslog(LOG_WARNING, "<warning> Config WARNING: Multiple response-maxlength settings found at line %d. The first setting will be used", linecount);
					continue;
					}
			
				i += strlen("response-maxlength");
				while ( line[i] == ' ' || line[i] == 9 ) i++;  // Skip spaces and tabs
				
				// ASCII values 48-57 represents numbers
				if ( !((line[i] >= 48 && line[i] <= 57)) ) {
					syslog(LOG_WARNING, "<warning> Config WARNING: Invalid response-maxlength value found in configuration file at line %d. Igonred", linecount);
					continue;
					}
				while ((line[i] >= 48 && line[i] <= 57)) { 
					if ( tmp > 5 )  {
						syslog(LOG_WARNING, "<warning> Config WARNING: Invalid response-maxlength value found in configuration file at line %d. Igonred", linecount);
						continue;
						}
					string_buffer[tmp++] = line[i++];
					}
				string_buffer[tmp]='\0';	
				confmod.SetResponseMaxLength(string_buffer);  // Try to set the loaded value
				}
			

			else syslog(LOG_WARNING, "<warning> Config WARNING: Unrecognised command at line %d", linecount);
			}
		fclose(file);

		/* Setting up default values for the necessary and not specified settings in configuration file */
		if (confmod.GetServerCount() == 0) {
			// Setting DNS servers to system defaults
			res_init();
			loginfo("No DNS server found in configuration file. Adding system defaults");
			for (k = 0; k<_res.nscount; k++)  { confmod.AddDNSServer(inet_ntoa(_res.nsaddr_list[k].sin_addr)); }
			}

		if (confmod.GetSelectionMode() != 1 && confmod.GetSelectionMode() != 2) {
			// Setting selection mode to round-robin mode
			loginfo("No DNS server selection mode has been set in configuration file. Setting it to round-robin");
			confmod.SetSelectionMode(2);
			}

		if (!strcmp(confmod.GetIpv6Addr(), "::1")) {
			// Setting up a DNS64 IPv6 address and prefix
			loginfo("No DNS64 IPv6 address has been configured. Setting it to 64:ff9b::/64");
			confmod.SetPrefix(96);
			confmod.SetIpv6Addr(const_cast<char*>("64:ff9b::"));
			}

		if (confmod.GetTimeoutSec() != 0 || confmod.GetTimeoutUsec() != 0) {
			// Printing out into log that Timout parameter has been set by configuration file
			syslog(LOG_INFO, "<info> Timeout time has been set to: %d.%d sec", confmod.GetTimeoutSec(), confmod.GetTimeoutUsec());
			}


		if (confmod.GetTimeoutSec() == 0 && confmod.GetTimeoutUsec() == 0) {
			// Setting up timeout-time paramteter to 1.2 sec 
			loginfo("Timeout parameter has not been configured. Setting it to 1.2 sec"); 
			confmod.SetTimeoutSec(const_cast<char*>("1"));
			confmod.SetTimeoutUsec(const_cast<char*>("200000"));
			}

		if (confmod.GetResendAttempts() == -1) {
			// Setting up the number DNS query resend attempt to 2
			loginfo("No resend-attempts configuration found. Setting it's value to 1");
			confmod.SetResendAttempts(const_cast<char*>("1"));
			}

		if (confmod.GetResponseMaxLength() == 0) {
			// Setting up the maximum length of IPv6 DNS response message to 512 byte
			loginfo("No response-maxlength configuration found. Setting it to 512 byte");
			confmod.SetResponseMaxLength(const_cast<char*>("512"));
			}

		loginfo("Configuration file has been successfully loaded");
		}
	else logerror("Config ERROR: cannot open config file (settings.conf)");

return;
}

