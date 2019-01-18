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
extern FILE *outputFile;

int e164_lookup_1number(char *phoneNumber) {

	//Construct the NAPTR query from the phone number
	int numberLength = strlen(phoneNumber);

	char phoneURI[numberLength * 2 + 1];
	phoneURI[numberLength * 2] = 0;
	char arpa[] = "e164.arpa";
	int i = numberLength - 1;
	int k = 0;
	for (i, k; k <= sizeof(phoneURI) - 1; i--, k += 2) {
		if (i < 0) break;
		phoneURI[k] = phoneNumber[i];
		phoneURI[k + 1] = '.';
	}

	char numberResource[strlen(phoneURI) + strlen(arpa) + 1];
	sprintf(numberResource, "%s%s", phoneURI, arpa);

	int retval = single_naptr_query(numberResource, phoneNumber);
	if(retval == 1) {
		return 1;
	} else {
		return 0;
	}
}

int e164_lookup_mnumbers(char *phone1, char *phone2) {

	struct timeval* startTime = (struct timeval*)malloc(sizeof(struct timeval));
	stopwatch_start(startTime);
	double i;
	double begin = atof(phone1);
	double end = atof(phone2);
	if (begin == 0.0 || end == 0.0 || begin == HUGE_VAL || end == HUGE_VAL)
		return -1;

	double count = 0.0;
	double sipCount = 0.0;
	for (i = begin; i <= end; i++, count++) {

		char curNumber[16] = {0};
		sprintf(curNumber, "%.0f", i);
		int result = e164_lookup_1number(curNumber);
		if (result == 1) {
			sipCount++;
		}
	}
	double elapsedSeconds = stopwatch_end(startTime);

	double queriesPerSecond = count / elapsedSeconds;
	double nonSIP = count - sipCount;
	double percentWith = sipCount / count * 100.0;
	double percentWithout = 100.0 - percentWith;
	printf("Total numbers checked: %.0f\nTotal numbers without SIP: %.0f (%.2f\%)\nTotal numbers with SIP: %.0f (%.2f\%)\n", count, nonSIP, percentWithout, sipCount, percentWith);
	printf("Time elapsed: %.3f seconds\nQueries per second: %.3f\n", elapsedSeconds, queriesPerSecond);
	if(output_set) {
		fprintf(outputFile, "Total numbers checked: %.0f\nTotal numbers without SIP: %.0f (%.2f\%)\nTotal numbers with SIP: %.0f (%.2f\%)\n", count, nonSIP, percentWithout, sipCount, percentWith);
		fprintf(outputFile, "Time elapsed: %.3f seconds\nQueries per second: %.3f\n", elapsedSeconds, queriesPerSecond);
	}

	free(startTime);
}

int single_naptr_query(char *lookup, char *phoneNumber) {

	u_char nsbuf[4096];
	char dispbuf[4096];
	ns_msg msg;
	ns_rr rr;
	int rrnum, length;

	length = res_query(lookup, ns_c_any, ns_t_naptr, nsbuf, sizeof(nsbuf));
	if(length < 0) {
			printf("No enum record found for '%s'.\n", phoneNumber);
			return 0;
	} else {

		if(verbose_set == 1) {
			printf("Parsing response of %d bytes:  ",length);
		}

		ns_initparse(nsbuf, length, &msg);
		int msg_count = ns_msg_count(msg, ns_s_an);
		for(rrnum = 0; rrnum < msg_count; rrnum++) {
			ns_parserr(&msg, ns_s_an, rrnum, &rr);
			ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
			if(verbose_set) {
				printf("%s\n", dispbuf);
			}

			u_int16_t rrlength = ns_rr_rdlen(rr);
			int targetlen = rrlength - 6;

			const u_char *record_data = ns_rr_rdata(rr);
			int offset;
			if(verbose_set) {
				printf("Found target of '");
			}
			for (offset = 6; offset < rrlength; offset++) {

				//if(offset == 6 && record_data[offset] == 0x03) {
				if(offset == 6 && record_data[offset]  < 32) {
					// do nothing if the first character is 0x03
				} else if (record_data[offset] < 32) {
					// Filtering out ASCII characters of ETX (end of text) or TAB (horitzontal tab)
					// These seem to represent the "." although I don't know 100% why yet
				} else {
					if(verbose_set) {
						printf("%c",record_data[offset]);
					}
				}
			}
			if(verbose_set) {
				printf("' for %s!\n", phoneNumber);
			}

			//If the record contains E2U+sip, parse out the SIP URI
			char *sipStr = strstr(record_data + 6, "E2U+sip");
			if (sipStr != 0) {
				char *sipURI = strstr(sipStr, "sip:");
				if (sipURI != 0) {
					char finalSipURI[strlen(sipURI)];
					strncpy(finalSipURI, sipURI, strlen(sipURI) - 1);
					finalSipURI[strlen(sipURI) - 1] = 0;
					printf("Found SIP URI '%s' for %s!\n", finalSipURI, phoneNumber);
					if(output_set) {
						fprintf(outputFile, "Found SIP URI '%s' for %s!\n", finalSipURI, phoneNumber);
					}
					return 1;
				}
			}
		}
	}
}
