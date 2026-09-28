#include <stdio.h>
#include <string.h>
#include "../src/ackprio.h"
static int P, F;
static void ok(const char *n, int got, int want){ if(got==want) P++; else { F++; printf("FAIL %s got %d want %d\n", n, got, want);} }
static void v4(unsigned char *b, int ihl, int doff, int payload, unsigned char flags, int frag){
  memset(b,0,200); b[0]=0x40|(ihl/4); int tot=ihl+doff+payload; b[2]=tot>>8; b[3]=tot; b[9]=6;
  if(frag){ b[6]=0x20; } unsigned char *t=b+ihl; t[12]=(doff/4)<<4; t[13]=flags; }
int main(void){ unsigned char b[200];
  v4(b,20,20,0,0x10,0); ok("v4 pure ack",ackprio_of(b,40),5);
  v4(b,20,32,0,0x10,0); ok("v4 ack+ts",ackprio_of(b,52),5);
  v4(b,20,20,100,0x18,0); ok("v4 data",ackprio_of(b,140),0);
  v4(b,20,20,0,0x12,0); ok("v4 synack",ackprio_of(b,40),0);
  v4(b,20,20,0,0x11,0); ok("v4 finack",ackprio_of(b,40),0);
  v4(b,20,20,0,0x14,0); ok("v4 rstack",ackprio_of(b,40),0);
  v4(b,20,20,0,0x10,1); ok("v4 fragment",ackprio_of(b,40),0);
  v4(b,20,20,0,0x10,0); b[9]=17; ok("v4 udp",ackprio_of(b,40),0);
  v4(b,20,20,0,0x10,0); ok("v4 short",ackprio_of(b,19),0);
  v4(b,24,20,0,0x10,0); ok("v4 options",ackprio_of(b,44),5);
  memset(b,0,200); b[0]=0x60; b[4]=0; b[5]=20; b[6]=6; b[40+12]=5<<4; b[40+13]=0x10; ok("v6 pure ack",ackprio_of(b,60),5);
  b[5]=120; ok("v6 data",ackprio_of(b,160),0);
  b[5]=20; b[6]=0; ok("v6 hbh",ackprio_of(b,60),0);
  printf("RESULT test_ackprio checks=%d failures=%d\n", P+F, F); return F!=0; }
