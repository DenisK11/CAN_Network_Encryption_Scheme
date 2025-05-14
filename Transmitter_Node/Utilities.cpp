#include "Utilities.h"

void showMessage(unsigned char* msg)
{
    unsigned char i = 0;
    unsigned char j = 1;

    if (j == 0)
    {
        for (i = 0; i < 16; i++)
            printf("%02X ", msg[i]);
    }
    else
        while (msg[i] != NULL && msg[i] != '\0' && msg[i] != 204)
        {
            printf("%02X ", msg[i]);
            i++;
        }
    printf("\n");
}

void copyString(unsigned char* destination, unsigned char* source)
{
    unsigned char i;

    for (i = 0; i < 16; i++)
    {
        destination[i] = source[i];
    }
}

void showmatrix(unsigned char* temp)
{
    unsigned char i;

    for (i = 0; i < 16; i++)
    {
        i % 4 == 0 ? printf("\n") : false;
        printf("%X ", temp[i]);

    }
    printf("\n");
}

void copynString(unsigned char* destination, unsigned char* source, unsigned char charNum, int initStep)
{
    int i = initStep;
    unsigned char j = 0;
    while (source[i] != NULL && i < charNum + initStep + 1)
    {
        destination[j] = source[i];
        i++;
        j++;
    }

    if (source[i] == NULL)
        for(j; j < 16; j++)
            destination[j] = (unsigned char)1;

}

void appendString(unsigned char* destination, unsigned char* source)
{
    unsigned char i = 0;
    static unsigned char j = 0;

    while (destination[j] != NULL && destination[j] != (unsigned char)204)
        j++;

    while (source[i] != NULL && source[i] != (unsigned char)204)
    {
        if (destination[j + i] == NULL)
                destination[j + i] = source[i];
        i++;
    }
}

bool checkPadding(unsigned char* text, unsigned char key)
{
    unsigned char i = 0;
    bool retval = false;

    if (text[15] != NULL && text[15] != (unsigned char)1)
        return true;

    if (text[15] == NULL && key != 0)
    {
        for (i = 0; i < 16; i++)    // Add padding to the text if it has less than 16 bytes
            if (text[i] == NULL)    // but not to the key, do not compromise on security
                text[i] = (unsigned char)1;
        retval = true;
    }
    else if (text[16] != NULL && key != 0 && text[16] != (unsigned char)204 && text[15] != (unsigned char)1) // Continue the algorithm if there is a text block > 16 bytes
        return true;

    else if (key == 0 && text[15] == NULL)    // Detect if the key is incompatible, DO NOT USE NULL IN YOUR KEY OR TEXT
    {
        printf("\nIncopatible key");
        return false;
    }
    else if (key == 0 && text[15] != NULL)
        return true;

    return retval;
}

void removePadding(unsigned char* msg)
{
    int i = 0;

    while (msg[i] != NULL && msg[i] != (unsigned char)1)
        i++;

    msg[i] = '\0';

}

// Modular Euclidian division to avoid overflow
int modinv(int a, int b)
{
    int bezout_t = 0, bezout_newt = 1;
    int remainder = b, new_remainder = a;

    int temp;
    int quotient;

    while (new_remainder != 0)
    {
        quotient = remainder / new_remainder;   // need a lot of math to explain, just trust the first comment
        temp = bezout_t;
        bezout_t = bezout_newt;
        bezout_newt = temp - quotient * bezout_newt;

        temp = remainder;
        remainder = new_remainder;
        new_remainder = temp - quotient * new_remainder;
    }

    if (remainder > 1)
        return -1; // not invertible

    if (bezout_t < 0)
        bezout_t += b;

    return bezout_t;
}

// Modular exponentiation to avoid overflow
int modpow(int base, int exp, int mod)
{
    int result = 1;

    base %= mod;

    if (base % mod == 0)    // avoid an infinite loop, learnt it the hard way
        return 0;
    else
        while (exp > 0)
        {
            if (exp & 1)
                result = (result * base) % mod; // need a lot of math to explain, just trust the first comment

            base = (base * base) % mod;
            exp >>= 1;
        }

    return result;
}