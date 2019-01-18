/*

VIPER Lab research and pentest tool
Released under BSD style licensea

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

int mx_lookup_1domain(char *domain) {

	int retval = mx_queries(domain);

	return retval;

}

int mx_lookup_mdomains(char *inputPath) {

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
	double mxCount = 0.0;

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
		int retval = mx_lookup_1domain(domain);

		// If at least 1 SRV query returns, then increment the domain count
		if(retval == 1) {
			mxCount++;

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

	double nonMX = totalCount - mxCount;
	double percentWith = mxCount / totalCount * 100.0;
	double percentWithout = 100.0 - percentWith;
	printf("Total domains checked:  %.0f\nTotal numbers without MX:  %.0f (%.2f\%)\nTotal numbers with MX:  %.0f (%.2f\%)\n", totalCount,nonMX,percentWithout, mxCount, percentWith);

        printf("Time elapsed: %.3f seconds\nQueries per second: %.3f\n", elapsedSeconds, queriesPerSecond);
        free(startTime);

	//print output to logfile
	if(output_set) {
		fprintf(outputFile, "Total domains checked:  %.0f\nTotal numbers without MX:  %.0f (%.2f\%)\nTotal numbers with MX:  %.0f (%.2f\%)\n", totalCount,nonMX,percentWithout, mxCount, percentWith);
        	fprintf(outputFile,"Time elapsed: %.3f seconds\nQueries per second: %.3f\n", elapsedSeconds, queriesPerSecond);
	}

}
int mx_queries(char *domain) {

	int retval = single_mx_query(domain);

	if(retval) {
		return 1;
	} else {
		return -1;
	}

}
int single_mx_query(char *domain) {

        u_char nsbuf[4096];
        char dispbuf[4096];
        ns_msg msg;
        ns_rr rr;
        int rrnum, length;

	    _res.retry = 1;
	    length = res_query(domain, ns_c_in, ns_t_mx, nsbuf, sizeof(nsbuf));

        if(length < 0) {
                //perror (domain);
        	if(verbose_set) {
                	printf("No MX records found for '%s'.\n",domain);
        	}
        	return -1;
        } else {

		ns_initparse(nsbuf, length, &msg);
		int msg_count = ns_msg_count(msg, ns_s_an);
		for(rrnum = 0; rrnum < msg_count; rrnum++) {
			ns_parserr(&msg, ns_s_an, rrnum, &rr);
			/* Check to make sure response is Type of MX, since sometimes response type of CNAME received */
			u_int16_t mytype = ns_rr_type(rr);
			if(mytype == 15) {
				// Good, this is an MX type
			} else {
                                if(verbose_set) {
                                        printf("RR received ~ but no MX type for '%s'.\n",domain);
                                }
                                return -1;
                        }

			ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));

			//Parse the mx name out of dispbuf
			int count = strlen(dispbuf) - 2;
			while (1) {
                		if (dispbuf[count - 1] == ' ') {
                			break;
                		}
                		count--;
                	}
                	char mxName[strlen(dispbuf) - count];
                	mxName[strlen(dispbuf) - count - 1] = 0;
                	memcpy(mxName, dispbuf + count, sizeof(mxName) - 1);

			printf("Found target of %s for %s\n", mxName, domain);
			if(output_set) {
				fprintf(outputFile,"Found target of %s for %s\n", mxName, domain);
				fflush(outputFile);
			}
		}

        }

	return 1;

}
