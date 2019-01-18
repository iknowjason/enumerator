/*

VIPER Lab research and pentest tool
Released under BSD style license

*/

#include "globals.h"
#include <netinet/in.h>
#include <resolv.h>
#include <math.h>

//Variables
extern int verbose_set;
extern int output_set;
extern int domaintextfile_set;
extern FILE *inputFile;
extern FILE *outputFile;
extern FILE *domainsFile;

int srv_lookup_1domain(char *domain) {

	int retval = srv_queries(domain);

	return retval;

}

int srv_lookup_mdomains(char *inputPath) {

	// Check to see if file exists
	int result = open_file(inputPath);
	if (result < 0) {
		printf("The input file %s could not be opened!\nPlease verify that it exists\n\n",inputPath);
		close_file(inputFile);
		close_file(outputFile);
		exit(1);
	}

	// Read in each line of the file and do the SRV lookup for each domain (line) in the file
	char buffer[100];
	double totalCount = 0.0;
	double srvCount = 0.0;

	// Read the number of lines in file, to get an idea of amount of work
	// So that we can track progress in realtime
	int lc = test_file_wc(inputPath);
	printf("Parsed %d domains in text file, %s\n",lc,inputPath);

        //Begin the stopwatch
        struct timeval* startTime = (struct timeval*)malloc(sizeof(struct timeval));
	stopwatch_start(startTime);

	while(fgets(buffer, 100, inputFile) != 0) {

		char domain[strlen(buffer)];
		strncpy(domain, buffer, strlen(buffer) - 1);
		domain[strlen(buffer) - 1] = 0;

		// Do the lookup on a single domain (currently there are 4 SRV queries per domain)
		int retval = srv_lookup_1domain(domain);
		
		// If at least 1 SRV query returns, then increment the domain count
		if(retval == 1) {
			srvCount++;

			// if the domain textfile output option is set, output only domain to a text file
			if(domaintextfile_set) {

				if(domainsFile) {
					fprintf(domainsFile,"%s\n",domain);
					fflush(domainsFile);
				}
			}
		}

		//increment totalCount
		totalCount++;

		// print the line we are on for work, and percentage complete
		printf("Querying %.0f of %d total domains ~ ",totalCount,lc);
		double workComplete = totalCount / lc * 100;
		printf("%.2f\% \n",workComplete);

		//print output to logfile
		if(output_set) {
			fprintf(outputFile, "Querying %.0f of %d total domains ~ ",totalCount,lc);
			fprintf(outputFile, "%.2f\% \n",workComplete);
		}
	}

        double elapsedSeconds = stopwatch_end(startTime);
        double queriesPerSecond = totalCount / elapsedSeconds;

	double nonSRV = totalCount - srvCount;
	double percentWith = srvCount / totalCount * 100.0;
	double percentWithout = 100.0 - percentWith;
	printf("Total domains checked:  %.0f\nTotal numbers without SRV:  %.0f (%.2f\%)\nTotal numbers with SRV:  %.0f (%.2f\%)\n", totalCount,nonSRV,percentWithout, srvCount, percentWith);

        printf("Time elapsed: %.3f seconds\nQueries per second: %.3f\n", elapsedSeconds, queriesPerSecond);
        free(startTime);

	//print output to logfile
	if(output_set) {
		fprintf(outputFile, "Total domains checked:  %.0f\nTotal numbers without SRV:  %.0f (%.2f\%)\nTotal numbers with SRV:  %.0f (%.2f\%)\n", totalCount,nonSRV,percentWithout, srvCount, percentWith);
        	fprintf(outputFile,"Time elapsed: %.3f seconds\nQueries per second: %.3f\n", elapsedSeconds, queriesPerSecond);
	}

}
int srv_queries(char *domain) {

        char srv_query1[100];
        char srv_query2[100];
        char srv_query3[100];
        char srv_query4[100];
        char *query1 = "_sip._udp";
        char *query2 = "_sip._tcp";
        char *query3 = "_sip._tls";
        char *query4 = "_sipfederationtls._tcp";

	sprintf(srv_query1, "%s.%s", query1, domain);
        sprintf(srv_query2, "%s.%s", query2, domain);
        sprintf(srv_query3, "%s.%s", query3, domain);
        sprintf(srv_query4, "%s.%s", query4, domain);

	int retval1, retval2, retval3, retval4;
	retval1 = single_srv_query(srv_query1, domain);
	retval2 = single_srv_query(srv_query2, domain);
	retval3 = single_srv_query(srv_query3, domain);
	retval4 = single_srv_query(srv_query4, domain);

	// if at least 1 of the 4 return values for SRV queries is 1, meaning the domain returns at least 1 SRV record, then return true to this function
	if( retval1 == 1 || retval2 == 1 || retval3 == 1 || retval4 == 1) {
		return 1;
	} else {
		return -1;
	}

}
int single_srv_query(char *lookup, char *domain) {

        u_char nsbuf[4096];
        char dispbuf[4096];
        ns_msg msg;
        ns_rr rr;
        int rrnum, length;

	_res.retry = 1;
	//length = res_query(lookup, ns_c_any, ns_t_srv, nsbuf, sizeof(nsbuf));
	length = res_query(lookup, ns_c_in, ns_t_srv, nsbuf, sizeof(nsbuf));

        if(length < 0) {
                //perror (domain);
		if(verbose_set) {
                	printf("No srv record found for '%s'.  Record:  %s\n",domain,lookup);
		}
		return -1;
        } else {

                ns_initparse(nsbuf, length, &msg);
                int msg_count = ns_msg_count(msg, ns_s_an);
                for(rrnum = 0; rrnum < msg_count; rrnum++) {
                        ns_parserr(&msg, ns_s_an, rrnum, &rr);
			/* Check to make sure response is Type of SRV, since sometimes responses are received for CNAME */
			u_int16_t mytype = ns_rr_type(rr);
			if(mytype == 33) {
				// Good, this is an SRV type
			} else {
				//printf("Boo!  I am not an SRV type!!!\n");
				if(verbose_set) {
                			printf("RR received ~ but no SRV type for '%s'.  Record:  %s\n",domain,lookup);
				}
				return -1;
			}
			/* End of check for type of SRV */

                        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
			if(verbose_set) {
                        	printf("%s\n", dispbuf);
			}

                        u_int16_t rrlength = ns_rr_rdlen(rr);
                        int targetlen = rrlength - 6;

                        const u_char *record_data = ns_rr_rdata(rr);
                        int offset;
			printf("Found target of '");
			if(output_set) {
				fprintf(outputFile,"Found target of '");
				fflush(outputFile);
			}
                        for (offset = 6; offset < rrlength; offset++) {

                                if(offset == 6 && record_data[offset]  < 32) {

                                } else if (record_data[offset] < 32) {
                                        printf(".");
                                } else {
                                        printf("%c",record_data[offset]);
                                }

				if(output_set) {
                                	if(offset == 6 && record_data[offset]  < 32) {

                                	} else if (record_data[offset] < 32) {
                                        	fprintf(outputFile,".");
                                	} else {
                                        	fprintf(outputFile,"%c",record_data[offset]);
                                	}
					fflush(outputFile);
				}
                        }
			printf("' for domain %s!  Record:  %s\n",domain,lookup);
			
			if(output_set) {
				fprintf(outputFile,"' for domain %s!  Record:  %s\n",domain,lookup);
			}
                }

        }
	
	return 1;

}
