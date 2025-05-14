#include "ECDH.h"

extern Point POINT_AT_INFINITY;

bool isOnCurve(Point P)
{
    if (P.isInfinity)
        return true;
    else if ((modpow(P.x, 3, _PRIME_FIELD) +  _A * P.x % _PRIME_FIELD + _B) % _PRIME_FIELD - P.y * P.y % _PRIME_FIELD == 0)
	{
		printf("True");
		return true;
	}
	else
	{
		printf("False");
		return false;
	}
}

// Point addition and doubling
Point point_add(Point P, Point Q) 
{
    if (P.isInfinity)
        return Q;
    else if (Q.isInfinity)
        return P;
    else if (P.x == Q.x && (P.y + Q.y == 0))
        return POINT_AT_INFINITY;

    Point temp;

    int lambda_num;
    int lambda_den;
    int lambda;

    if (P.x != Q.x && P.y != Q.y)
    {
        lambda_num = field_abs(Q.y - P.y);
        lambda_den = modinv(field_abs(Q.x - P.x), _PRIME_FIELD);

        lambda = lambda_num * lambda_den % _PRIME_FIELD;
    }
    else
    {
        lambda_num = field_abs(3 * field_abs(P.x * P.x) + _A);
        lambda_den = modinv(field_abs(2 * P.y), _PRIME_FIELD);

        lambda = lambda_num * lambda_den % _PRIME_FIELD;
    }

    temp.x = (lambda * lambda - P.x - Q.x + 2 * _PRIME_FIELD) % _PRIME_FIELD; // adding the _PRIME_FIELD in order to ensure
    temp.y = (lambda * (P.x - temp.x) - P.y + 2 * _PRIME_FIELD) % _PRIME_FIELD; // that we do not get a negative modulus
    temp.isInfinity = false;

    return temp;
}

// Scalar multiplication
Point scalar_mult(int k, Point P) 
{
    Point R = POINT_AT_INFINITY; 

    while (k > 0) 
    {
        if (k & 1) 
            R = point_add(R, P);    // double and add algorithm

        P = point_add(P, P);
        k >>= 1;
    }
    return R;
}

int field_abs(int x)
{
    x %= _PRIME_FIELD;

    if (x < 0) 
        x += _PRIME_FIELD;
    else
    {

    }

    return x;
}

void bad_hash(unsigned char* key, int generator)
{
    int i;

    for (i = 0; i < 16; i++)
        key[i] ^= generator + key[(i + 1) % 16];
}