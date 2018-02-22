
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

	bdConvFromDecimal(n1, "514745167025222387434132377137056715954750729807151447929894289695587285793889099978536904494455862473045694392353612260528582074521711735864082380505874261026769465596315849668245703081452047808798727647904141791488099702631575692170683102622471798376397440600292225038412176681344166204027842724877162681931");
	bdConvFromDecimal(n2, "332459552799915544356022641605448137617079921391832222557892949808060953028449422328281413629912335051440744955455010851012308918294549765005480121061697711447087615327860789708246235156912421474047484838827777697938563515420810650393553528058831317409340577149233554235346445890238642955390137465511286414033");
	bdConvFromDecimal(n3, "665701912162243069059653781669230805473457427767514323262762891771122352328706695409103713864384833437438648120217615990765220365745013739246022203593234785338178963805463643869398986119431772931646042972240277833431035018628949924813463553419243108837309078316455504749755062865258063926243606206806549969161");
	
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
	
    bdConvFromDecimal(c1, "159610386572167689266326385036487109027500941380400104125191262882664358398577536610497671009102596940624920315091422093100238619835848693651492344785000232303139338861093680138737091249739575100655219967271819921458016154329847843423233652818852580016834561970850695063090000199448970052668647861992230109134");
	bdConvFromDecimal(c2, "80704323590708576386562863656130406931573788060159775931074197125212042930440694778363300836637666152530601069635539711403775897104413839059003511049631024172974390473641408894970527777947213128650545118958630567223577806350516381008539951304600069024003674444114727988917350720932569342357635015732615468372");
	bdConvFromDecimal(c3, "290728542387622789691059470283422806073663108257730190721270583629901119139049111765276898786687400514004023098315787810926656039376046957101984075353288285867739293190825676944209163087896697394093577432590616749562076462942759742984949258019827469729922204479107792698042941392668070743176808454529741938138");
		

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
	//Step 5 Compute M^3 mod N
	
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
	bdPrintDecimal("Message Decimal = ",M, "\n\n");
	//Compute the cuberoot to obtain the message

	bdCubeRoot(t, M);
bdPrintHex("Cuberoot of M , Plain Text in Hex form : ", t, "\n\n");


/*
------------Print in String format with spaces----------------

This is done by converting the string into 2 byte arrays 
And converting each of them into a character 
Read input in hexadecimal format and print the corresponding String

*/

char *s1 = (char*)malloc(1024);

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

