
#include <stdio.h>
#include "bigd.h"
#include "bigdigits.h"
#include <string.h>
#include<ctype.h>
#include<stdlib.h>

#define assert(x) while (0) { }

void main(void)
{
	BIGD e, n1, n2, n3, c1, c2, c3, N, N1, N2, N3, d1, d2, d3, s, t, M;
	        
	 
	//Three different Public key values n1, n2, n3 
	
	n1 = bdNew();
	n2 = bdNew();
	n3 = bdNew();

	bdConvFromHex(n1, "009623511e6769644d693e89f692ffc2558eef121d42ca98699781e139e29c2e1aa58d8883bbdba41165fdeb85a9a5648fc29a65d59e9401694dd11ae205f0ce3b");
	bdConvFromHex(n2, "00ad4bc0f980f4523f490fc40c12efcecc1e8af67890b6562449876e8e091e861cda699e5a8eb309b0a9d6b293100c1229fbd18a5951f33b6fbab1fd8d90f7c829");
	bdConvFromHex(n3, "00b7223364d88353ec02b0850e8a01d2ba9ca2663c32c15df7b596406c6fc1c171ac965a554b8b338f4bb046c543937b4b19c699864f1d0dd4be0177eccce0bb57");
	
	printf("\n\n-----------------------------Obtaining PlainText from Broadcast Low Public Exponent Attack---------------------------------------\n\n\n");
	printf("The public modulus values\n\n");
	bdPrintDecimal("n1=", n1, "\n\n");
	bdPrintDecimal("n2=", n2, "\n\n");
	bdPrintDecimal("n3=", n3, "\n\n");


	// Public key exponent e=3

	e = bdNew();	

	bdSetShort(e, 3);
	bdPrintHex("Low public exponent e= ", e, "\n\n");
	
	// Given three cipher text
		
	c1 = bdNew();
	c2 = bdNew();
	c3 = bdNew();
	
    bdConvFromHex(c1, "34d2fc2fa4785e1cdb1c09c9a5db98317d702aaedd2759d96e8938f740bf982e2a42b904e54dce016575142f1b0ed112cc214fa8378b0d5eebc036dc7df3eeea");
	bdConvFromHex(c2, "3ddd68eeff8be9fee7d667c3c0ef21ec0d56cefab0fa10199c933cffbf0924d486296c604a447f48b9f30905ee49dd7ceef8fc689a1c4c263c1b3a9505091b00");
	bdConvFromHex(c3, "956f7cbf2c9da7563365827aba8c66dc83c9fb77cf7ed0ca225e7d155d2f573d6bd18e1c18044cb14c59b52d3d1f6c38d8941a1d58942ed7f13a52caccc48154");
		

	//Printing the Cipher Text

    printf("The ciphertexts are: \n");
	bdPrintHex("c1=", c1, "\n\n");
	bdPrintHex("c2=", c2, "\n\n");
	bdPrintHex("c3=", c3, "\n\n");

	
// Step 1: Checking if pair-wise co prime
// bdGCD function checks if co prime and stores the result in t which should be 1 to use Chinese Reminder Theorem

	t = bdNew();
	
	bdGcd(t, n1, n2);
	bdPrintDecimal("gcd(n1,n2)=", t, "\n");
	assert(bdShortCmp(t,1)==0);
	bdGcd(t, n2, n3);
	bdPrintDecimal("gcd(n2,n3)=", t, "\n");
	assert(bdShortCmp(t,1)==0);
	bdGcd(t, n3, n1);
	bdPrintDecimal("gcd(n3,n1)=", t, "\n");
	assert(bdShortCmp(t,1)==0);
	printf("n1,n2 and n3 are pairwise coprime\n\n");


 // Step 3 Compute N = n1 * n2 * n3 
   	N = bdNew();
	
	bdMultiply(t, n1, n2);
	bdMultiply(N, t, n3);
	
	bdPrintHex("N=", N, "\n\n");

	// Compute N1, N2 and N3
	N1 = bdNew();
	N2 = bdNew();
	N3 = bdNew();

	
	bdMultiply(N1, n2, n3);
   	bdMultiply(N2, n1, n3);
	bdMultiply(N3, n1, n2);

	// Step 5 Compute d1= N1 inv mod n1, d2= N2 inv mod n2 , d3= N3 inv mod n3 
	
	d1 = bdNew();
	d2 = bdNew();
	d3 = bdNew();

	
	bdModInv(d1, N1, n1);
	bdModInv(d2, N2, n2);
	bdModInv(d3, N3, n3);
	

	// Step 6 Compute M = c1* N1* d1 + c2* N2* d2 + c3* N3* d3 (mod N) 
	
	M = bdNew();
	s = bdNew();	
	
	bdModMult(s, c1, N1, N);
	bdModMult(M, s, d1, N);
	bdModMult(s, c2, N2, N);
	bdModMult(t, s, d2, N);
	
	bdAdd_s(M, M, t);

	bdModMult(s, c3, N3, N);
	bdModMult(t, s, d3, N);

	bdAdd_s(s, M, t);

	bdModulo(M, s, N);

	bdPrintHex("Message = ", M, "\n\n");

	//Compute the cuberoot to obtain the message

	bdCubeRoot(t, M);
    bdPrintHex("Cuberoot of M , Plain Text in Hex form : ", t, "\n\n");


/*
------------Print in String format with spaces----------------

This is done by converting the string into 2 byte arrays 
And converting each of them into a character 
Read input in hexadecimal format and print the corresponding String

*/

char *s1 = (char*)malloc(128);

bdConvToHex(t,s1,127);

 unsigned char *src;

  src=s1;
  
  char buffer[63]; // Hold the first byte in the buffer
  char *dst = buffer;
  char *end = buffer + sizeof(buffer); // Takes care of the last character
  unsigned int u;

 printf("Cracked Plaintext = ");
 
   while (dst < end && sscanf(src, "%2x", &u) == 1)
    {
        *dst++ = u;
        src += 2;
    }

    for (dst = buffer; dst < end; dst++)
        printf("%c",
               (isprint(*dst) ? *dst : '.'));
   printf("\n");

//FFor every bdNew() corresponding Free function clean_up

	bdFree(&e);
	bdFree(&t);

	bdFree(&n1);
	bdFree(&n2);
    bdFree(&n3);

	bdFree(&c1);
	bdFree(&c2);
	bdFree(&c3);

	bdFree(&N);

	bdFree(&N1);
	bdFree(&N2);
	bdFree(&N3);

	bdFree(&d1);
	bdFree(&d2);
	bdFree(&d3);

	bdFree(&s);

	bdFree(&M);
	
	}

