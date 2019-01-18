#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

//Utility functions
void stopwatch_start(struct timeval*);
double stopwatch_end(struct timeval*);
