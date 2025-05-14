#pragma once
#include "Utilities.h"

#define _A 0
#define _B 7
#define _PRIME_FIELD 223

typedef struct
{
	int x;
	int y;
	bool isInfinity;
}Point;

#ifdef __cplusplus
extern "C" {
#endif

	static Point POINT_AT_INFINITY = { 0, 0, true };

#ifdef __cplusplus
}
#endif

bool isOnCurve(Point P);
int field_abs(int x);

Point scalar_mult(int k, Point P);
Point point_add(Point P, Point Q);
void bad_hash(unsigned char* key, int generator);