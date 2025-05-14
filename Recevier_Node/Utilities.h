#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>

using namespace std;

// This header will continue to grow with more and more utilities that will make debugging easier
// probably will add some unit tests in the future using CMAKE and GTest

#ifdef __cplusplus
extern "C" {
#endif

	static FILE* CSV_file;

#ifdef __cplusplus
}
#endif


void showmatrix(unsigned char* temp);
void showMessage(unsigned char* msg);
void copyString(unsigned char* destination, unsigned char* source);
bool checkPadding(unsigned char* text, unsigned char key);
void copynString(unsigned char* desitnation, unsigned char* source, unsigned char charNum, int initStep);
void appendString(unsigned char* destination, unsigned char* source);
void removePadding(unsigned char* msg);
void generate_elipse_points(int starting_point, int order);

int modpow(int base, int exp, int mod);
int modinv(int a, int b);
