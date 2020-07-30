//============================================================================
// Name        : main.cpp
// Author      : James Ren
// Version     : 0.1
// Description : Paillier cryptosystem in C
//============================================================================

#include <string>
#include <iostream>
#include <time.h>
using namespace std;

#define BILLION 1E9
#define THOUSAND 1000.0


string* ltrim(string* str, const string& chars = "\t\n\v\f\r ")
{
    str->erase(0, str->find_first_not_of(chars));
    return str;
}

string* rtrim(string* str, const string& chars = "\t\n\v\f\r ")
{
    str->erase(str->find_last_not_of(chars) + 1);
    return str;
}

string* trim(string* str, const string& chars = "\t\n\v\f\r ")
{
    return ltrim(rtrim(str, chars), chars);
}

int main()
{
	struct timespec ts_start, ts_end;


	printf("*********************** C performance test *********************** \n\n");

	clock_gettime(CLOCK_MONOTONIC, &ts_start);



	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	printf("C time elapsed in microsecond: %.3f \n\n", ( ts_end.tv_nsec - ts_start.tv_nsec ) / THOUSAND);

	printf("*********************** End of test *********************** \n");

	return 0;
}
