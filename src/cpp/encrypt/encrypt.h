#pragma once 
#include <iostream>
#include "memory.h"  
using namespace std;

typedef unsigned char BYTE;

// Input: keyByte, dataByte
// Output: unsigned char - encryptDataByte
void des_encrypt(BYTE *keyByte, BYTE *dataByte, BYTE *encryptDataByte);

// Quick demo for DES encrypt/decrypt
void des_demo();

void reverse_byBit(BYTE *out, const BYTE *in);
void reverse_byByte(BYTE *out, const BYTE *in);

void printHexByBits(bool *in_bool, unsigned int size);
void printHexByByte(BYTE *in, unsigned int size);