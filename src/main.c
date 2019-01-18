/*

VIPER Lab research and pentest tool
Released under BSD style license

*/
#include "globals.h"

// Declare some globals
int srv_set;
int mx_set;
int enum_set;
int net_set;
int verbose_set;
int domain_set;
int list_set;
int enum_set;
int number_set;
int output_set;
int domaintextfile_set;
char *domainname;
char *phoneNumber;
char *inputPath;
char *outputPath;
char *domainsoutputPath;
FILE *inputFile;
FILE *inputCountFile;
FILE *outputFile;
FILE *domainsFile;
FILE *pidFile;

// Function declarations
void process_arguments();
void close_file(FILE*);
int create_file(char*);
int open_file(char*);
void enum_range_lookup(char*);
void enum_single_lookup(char*);
int create_pid();
int delete_pid(int pid_numeric);

// Declared in srv.c
extern int srv_lookup_1domain(char *domainname);
extern int srv_lookup_mdomains(char *inputPath);

// Declared in enum.c
extern int e164_lookup_1number(char *phoneNumber);
extern int e164_lookup_mnumbers(char *phone1, char *phone2);

//Declared in mx.c
extern int mx_lookup_1domain(char *domainname);
extern int mx_lookup_mdomains(char *inputPath);

int main (int argc, char *argv[])
{

	char o;

	while ((o = getopt(argc,argv, "smd:kl:er:n:vo:z:")) > 0) {
	switch(o){
	case 's':
		// SRV lookup enabled
		srv_set = 1;
		break;
	case 'm':
		// MX lookup enabled
		mx_set = 1;
		break;
	case 'd':
                // Domain for SRV lookup
                domain_set = 1;
                domainname = optarg;
                /* Causing problems for some strings with garbage characters */
                //domainname = malloc(strlen(optarg));
                //strcpy(domainname,optarg);
                /* End of causing problems */
		break;
	case 'l':
		// Text list for  input
		list_set = 1;
		inputPath = optarg;
		//inputPath = malloc(strlen(optarg));
		//strcpy(inputPath, optarg);
		break;
	case 'k':
		// Kill all enumerator processes
		kill_pids();
		exit(1);
	case 'e':
		// ENUM lookups
		enum_set = 1;
		break;
	case 'n':
		// Network discovery
		break;
	case 'r':
		//Single phone number or phone number range
		number_set = 1;
		phoneNumber = malloc(strlen(optarg));
		strcpy(phoneNumber, optarg);
		break;
	case 'v':
		// Enable debug or verbose mode
		verbose_set = 1;
		break;
	case 'o':
		//Write results to file specified by optarg
		output_set = 1;
		outputPath = malloc(strlen(optarg)*sizeof(char));
		outputPath = optarg;
		break;
	case 'z':
		// Write output of domains text file
		domaintextfile_set = 1;
		domainsoutputPath = malloc(strlen(optarg)*sizeof(char));
		domainsoutputPath = optarg;
		break;
		
	default:
		break;
	}
	}

	int pid_numeric = create_pid();

	process_arguments();
	close_file(inputFile);
	close_file(outputFile);
	int retval = delete_pid(pid_numeric);
	return 1;

}
void kill_pids() {

	char pidPath[100]; 
	char *path = "/var/run/enumerator";

	int i;
	for (i = 0; i < 10000; i++) {

		sprintf(pidPath,"%s%d.pid",path,i);		
		int retval = file_exists(pidPath);
		if(retval == 1) {

			//need to kill
			char pid[100];
			pidFile = fopen(pidPath, "r");
			fgets(pid, 100, pidFile);

			// kill command
			//printf("Killing pid of %s, file is %s ~ ",pid,pidPath);
			char killCmd[100];
			char *cmd = "kill";
			sprintf(killCmd,"%s %s",cmd,pid);
			int retval = system(killCmd);
			//printf("Returned %d\n",retval);
			retval = remove(pidPath);
			fclose(pidFile);	

		} else {


		}

	}

}
int delete_pid(int pid_numeric) {

        char pidPath[100];
        char *path = "/var/run/enumerator";
	sprintf(pidPath,"%s%d.pid",path,pid_numeric);		
	
	//int test = file_exists(pidPath);
	int retval = remove(pidPath);
	if(retval == 1) {
		//printf("Deleted pid file of %s\n",pidPath);
		return 1;
	} else {
		return -1;
		// Unable to delete pidfile

	}


}
int create_pid() {

	int myPid = getpid();	

	char pidPath[100]; 
	char *path = "/var/run/enumerator";
	
	int i;
	for (i = 0; i < 10000; i++) {

		sprintf(pidPath,"%s%d.pid",path,i);		

		int retval = file_exists(pidPath);
		if(retval == 1) {
			//It already exists
			//printf("Enumerator pid file %s already exists\n",pidPath);

		} else {

			// It doesn't exist, so create a new PID
			//printf("Enumerator pid file %s doesn't exist ~ writing new PID of %d\n",pidPath,myPid);
			pidFile = fopen(pidPath, "w");
			if(pidFile == 0) {
				//printf("The specified pid file could not be opened for writing!\nPlease check that is a valid path\npidPath:  %s\n\n",pidPath);
				exit(1);
			} else {

				fprintf(pidFile,"%d",myPid);
				fclose(pidFile);
				return i;
			}
		}
	}

}
void process_arguments() {

        if(!enum_set && !srv_set && !net_set && !mx_set) {

                printf("SRV, ENUM, or MX lookups, or network discovery must be specified\n");
                exit(1);
        }

	if (output_set) {

		int result = create_file(outputPath);
		if (result < 0) {
			printf("The specified output file could not be opened or created for writing!\nPlease check that it is a valid path.\n\n");
			exit(1);
		}

	}

	if (domaintextfile_set) {

		// When this option is set, we we will make sure that domains with SRV will output to a dedicated text file
		//make sure srv and a list input file is set
		if((srv_set || mx_set) &&  list_set) {

			domainsFile = fopen(domainsoutputPath, "w");
			if (domainsFile == 0) {
				printf("The specified output file could not be opened or created for writing!\nPlease check that it is a valid path.\n\n");
				exit(1);
			}

		} else {

			printf("A domain text file can only work by enabling srv (-s) or mx (-m) and input domain list (-l domains.txt)\n");
			printf("Example:  enumerator -s -l domains.txt -z domains-discovered.txt\nExample:  enumerator -m -l domains.txt -z domains-with-mx.txt\n");
			exit (1);
		}
	}

	if(srv_set) {

		if(domain_set != 1 && list_set != 1) {
			printf("SRV option is enabled ~ also requires either Domain name lookup or input list of domains\n");
			printf("Sample usage:\nenumerator -s -d blah.com\nenumerator -s -l domains.txt\n\n");
			close_file(inputFile);
			close_file(outputFile);
			exit(1);

		} else if(domain_set == 1 && list_set == 1) {

			printf("SRV option is enabled with both Domain name lookup and input list of domains\nPlease select only one option\n");
			printf("Sample usage:\nenumerator -s -d blah.com\nenumerator -s -l domains.txt\n\n");
			close_file(inputFile);
			close_file(outputFile);
			exit(1);

		} else if(domain_set) {
			// srv lookup for a single domain
			int retval = srv_lookup_1domain(domainname);
						
		} else {
			// srv lookup domain list
			int retval = srv_lookup_mdomains(inputPath);
		}

	}
	else if(mx_set) {

		if(domain_set != 1 && list_set != 1) {
			printf("MX option is enabled ~ also requires either Domain name lookup or input list of domains\n");
			printf("Sample usage:\nenumerator -m -d blah.com\nenumerator -m -l domains.txt\n\n");
			close_file(inputFile);
			close_file(outputFile);
			exit(1);

		} else if(domain_set == 1 && list_set == 1) {

			printf("MX option is enabled with both Domain name lookup and input list of domains\nPlease select only one option\n");
			printf("Sample usage:\nenumerator -m -d blah.com\nenumerator -m -l domains.txt\n\n");
			close_file(inputFile);
			close_file(outputFile);
			exit(1);

		} else if(domain_set) {
			// srv lookup for a single domain
			int retval = mx_lookup_1domain(domainname);

		} else {
			// srv lookup domain list
			int retval = mx_lookup_mdomains(inputPath);
		}

	}
	else if(enum_set) {

		if(number_set != 1 && list_set != 1) {
			printf("ENUM option is enabled ~ also requires either range lookup or input list of phone numbers\n");
			printf("Sample usage:\nenumerator -e -r 15555555555\nenumerator -e -r 15555555555-16666666666\nenumerator -e -l numbers.txt\n\n");
			close_file(inputFile);
			close_file(outputFile);
			exit(1);
		} else if(number_set == 1 && list_set == 1) {
			printf("ENUM option is enabled with both range lookup and input list of phone numbers\nPlease select only one option\n");
			printf("Sample usage:\nenumerator -e -r 15555555555\nenumerator -e -r 15555555555-16666666666\nenumerator -e -l numbers.txt\n\n");
			close_file(inputFile);
			close_file(outputFile);
			exit(1);
		} else if(number_set) {

			//ENUM lookup for a single phone number or a range of phone numbers
			char* dash = strchr(phoneNumber, '-');
			if (dash != 0) {
				enum_range_lookup(phoneNumber);
			} else {
				enum_single_lookup(phoneNumber);
			}
		} else {
			//ENUM lookup for a list of phone numbers
			int result = open_file(inputPath);
			if (result < 0) {

				printf("The input file could not be opened!\nPlease verify that it exists\n\n");
				close_file(inputFile);
				close_file(outputFile);
				exit(1);
			}

			//Read in each line of the file and do the lookups. Each line should either be a range or a single number
			char buffer[100];
			while(fgets(buffer, 100, inputFile) != 0) {

				char phoneNumber[strlen(buffer)];
				strncpy(phoneNumber, buffer, strlen(buffer) - 1);
				phoneNumber[strlen(buffer) - 1] = 0;
				char* dash = strchr(phoneNumber, '-');
				if (dash != 0) {
					enum_range_lookup(phoneNumber);
				} else {
					enum_single_lookup(phoneNumber);
				}
				printf("\n");
			}
		}
	}

}

int open_file(char *filePath) {

	inputFile = fopen(filePath, "r");
	if (inputFile == 0) {
		return -1;
	}
}

int test_file_wc(char *filePath) {

	inputCountFile = fopen(filePath, "r");
	if(inputCountFile == 0) {
                printf("The input file %s could not be opened!\nPlease verify that it exists\n\n",inputPath);
		exit(1);
	}

	int myCount = 0;
	char buffer[100];
	while(fgets(buffer, 100, inputCountFile) != 0) {
		myCount++;
	}
	return myCount;	

        if (inputCountFile) {
                fclose(inputCountFile);
        }

}

int create_file(char *filePath) {

	outputFile = fopen(filePath, "w");
	if (outputFile == 0) {
		return -1;
	}
}

void close_file(FILE* file) {

	if (file) {
		fclose(file);
	}
}

void enum_range_lookup(char* phoneNumber) {

	//Range of phone numbers
	char dashChar[] = "-";
	int dashLocation = strcspn(phoneNumber, dashChar);
	if (dashLocation < 8) {
		printf("Invalid phone number range specified. The shortest phone number is at least 7 digits long\n\n");
		exit(1);
	}
	char phone1[dashLocation + 1];
	char phone2[strlen(phoneNumber) - dashLocation + 1];

	strncpy(phone1, phoneNumber, dashLocation);
	phone1[dashLocation] = 0;
	strncpy(phone2, phoneNumber + dashLocation + 1, strlen(phoneNumber) - dashLocation);

	//Check to make sure the phone number is a maximum of 15 digits
	if (strlen(phone1) > 15 || strlen(phone2) > 15) {
		printf("Invalid phone numbers specified: Phone numbers must have a maximum length of 15 digits.\n\n");
		close_file(inputFile);
		close_file(outputFile);
		exit(1);
	}

	if(output_set) {
		fprintf(outputFile, "Number block: %s\n", phoneNumber);
	}
	int retval = e164_lookup_mnumbers(phone1, phone2);
}

void stopwatch_start(struct timeval* now) {
        gettimeofday(now, NULL);
}

double stopwatch_end(struct timeval* begin) {
        struct timeval* end = (struct timeval*)malloc(sizeof(struct timeval));
        struct timeval* diff = (struct timeval*)malloc(sizeof(struct timeval));
        gettimeofday(end);

        diff->tv_sec = end->tv_sec - begin->tv_sec;
        diff->tv_usec = end->tv_usec - begin->tv_usec;
	double seconds = (double)(diff->tv_sec) + (double)diff->tv_usec / 1000000.0;

	free(diff);
        free(end);

        return seconds;
}


void enum_single_lookup(char* phoneNumber) {

	//Check to make sure the phone number is a maximum of 15 digits
	if (strlen(phoneNumber) > 15) {
		printf("Invalid phone number specified: Phone numbers must have a maximum length of 15 digits.\n\n");
		close_file(inputFile);
		close_file(outputFile);
		exit(1);
	}

	//Check to make sure phoneNumber is only numbers
	int i = 0;
	for (i; i < strlen(phoneNumber); i++) {
		if (phoneNumber[i] < 48 || phoneNumber[i] > 57) {
			printf("Invalid phone number specified: Phone numbers must contain only numbers with no dashes or spaces.\n\n");
			close_file(inputFile);
			close_file(outputFile);
			exit(1);
		}
	}
	int retval = e164_lookup_1number(phoneNumber);
}
int file_exists(const char * filename) {

	FILE *file;

	if( file = fopen(filename, "r")) {

		fclose(file);
		return 1;
	}

	return -1;

}
