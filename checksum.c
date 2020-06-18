#include <sys/types.h>

/**
 * Based on in_chksum() from Unix Network Programming by Stevens,
 * Fenner, and Rudoff
 **/

unsigned short checksum(unsigned short * data, int len){
  int i;
  unsigned int sum = 0;
  unsigned short * ptr;
  unsigned short chcksum;
  
  
  for(i=len, ptr=data; i > 1; i-=2){ //i-=2 for 2*8=16 bits at time
    sum += *ptr; //sum += 16 bit word at ptr
    ptr+=1;//move ptr to next 16 bit word
  }

  //check if we have an extra 8 bit word
  if (i == 1){
    sum += *((unsigned char*) ptr); //cast ptr to 8 bit unsigned char
  }

  //Fold the carry into the first 16 bits
  sum = (sum & 0xffff) + (sum >> 16);

  //Fold the last carry into the sum
  sum += (sum >> 16);

  // ~ compliments and return
  chcksum = ~sum;
  
  return chcksum;
}
